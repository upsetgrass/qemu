/*
 * qht.c - QEMU Hash Table, designed to scale for read-mostly workloads.
 *
 * Copyright (C) 2016, Emilio G. Cota <cota@braap.org>
 *
 * License: GNU GPL, version 2 or later.
 *   See the COPYING file in the top-level directory.
 *
 * Assumptions:
 * - NULL cannot be inserted/removed as a pointer value.
 * - Trying to insert an already-existing hash-pointer pair is OK. However,
 *   it is not OK to insert into the same hash table different hash-pointer
 *   pairs that have the same pointer value, but not the hashes.
 * - Lookups are performed under an RCU read-critical section; removals
 *   must wait for a grace period to elapse before freeing removed objects.
 *
 * Features:
 * - Reads (i.e. lookups and iterators) can be concurrent with other reads.
 *   Lookups that are concurrent with writes to the same bucket will retry
 *   via a seqlock; iterators acquire all bucket locks and therefore can be
 *   concurrent with lookups and are serialized wrt writers.
 * - Writes (i.e. insertions/removals) can be concurrent with writes to
 *   different buckets; writes to the same bucket are serialized through a lock.
 * - Optional auto-resizing: the hash table resizes up if the load surpasses
 *   a certain threshold. Resizing is done concurrently with readers; writes
 *   are serialized with the resize operation.
 *
 * The key structure is the bucket, which is cacheline-sized. Buckets
 * contain a few hash values and pointers; the u32 hash values are stored in
 * full so that resizing is fast. Having this structure instead of directly
 * chaining items has two advantages:
 * - Failed lookups fail fast, and touch a minimum number of cache lines.
 * - Resizing the hash table with concurrent lookups is easy.
 *
 * There are two types of buckets:
 * 1. "head" buckets are the ones allocated in the array of buckets in qht_map.
 * 2. all "non-head" buckets (i.e. all others) are members of a chain that
 *    starts from a head bucket.
 * Note that the seqlock and spinlock of a head bucket applies to all buckets
 * chained to it; these two fields are unused in non-head buckets.
 *
 * On removals, we move the last valid item in the chain to the position of the
 * just-removed entry. This makes lookups slightly faster, since the moment an
 * invalid entry is found, the (failed) lookup is over.
 *
 * Resizing is done by taking all bucket spinlocks (so that no other writers can
 * race with us) and then copying all entries into a new hash map. Then, the
 * ht->map pointer is set, and the old map is freed once no RCU readers can see
 * it anymore.
 *
 * Writers check for concurrent resizes by comparing ht->map before and after
 * acquiring their bucket lock. If they don't match, a resize has occurred
 * while the bucket spinlock was being acquired.
 *
 * Related Work:
 * - Idea of cacheline-sized buckets with full hashes taken from:
 *   David, Guerraoui & Trigonakis, "Asynchronized Concurrency:
 *   The Secret to Scaling Concurrent Search Data Structures", ASPLOS'15.
 * - Why not RCU-based hash tables? They would allow us to get rid of the
 *   seqlock, but resizing would take forever since RCU read critical
 *   sections in QEMU take quite a long time.
 *   More info on relativistic hash tables:
 *   + Triplett, McKenney & Walpole, "Resizable, Scalable, Concurrent Hash
 *     Tables via Relativistic Programming", USENIX ATC'11.
 *   + Corbet, "Relativistic hash tables, part 1: Algorithms", @ lwn.net, 2014.
 *     https://lwn.net/Articles/612021/
 */
#include "qemu/osdep.h"
#include "qemu/qht.h"
#include "qemu/atomic.h"
#include "qemu/rcu.h"
#include "qemu/memalign.h"

//#define QHT_DEBUG

/*
 * We want to avoid false sharing of cache lines. Most systems have 64-byte
 * cache lines so we go with it for simplicity.
 *
 * Note that systems with smaller cache lines will be fine (the struct is
 * almost 64-bytes); systems with larger cache lines might suffer from
 * some false sharing.
 */
#define QHT_BUCKET_ALIGN 64

/* define these to keep sizeof(qht_bucket) within QHT_BUCKET_ALIGN */
#if HOST_LONG_BITS == 32
#define QHT_BUCKET_ENTRIES 6
#else /* 64-bit */
#define QHT_BUCKET_ENTRIES 4
#endif

enum qht_iter_type {
    QHT_ITER_VOID,    /* do nothing; use retvoid */
    QHT_ITER_RM,      /* remove element if retbool returns true */
};

struct qht_iter {
    union {
        qht_iter_func_t retvoid;
        qht_iter_bool_func_t retbool;
    } f;
    enum qht_iter_type type;
};

/*
 * Do _not_ use qemu_mutex_[try]lock directly! Use these macros, otherwise
 * the profiler (QSP) will deadlock.
 */
static inline void qht_lock(struct qht *ht)
{
    if (ht->mode & QHT_MODE_RAW_MUTEXES) {
        qemu_mutex_lock__raw(&ht->lock);
    } else {
        qemu_mutex_lock(&ht->lock);
    }
}

static inline int qht_trylock(struct qht *ht)
{
    if (ht->mode & QHT_MODE_RAW_MUTEXES) {
        return qemu_mutex_trylock__raw(&(ht)->lock);
    }
    return qemu_mutex_trylock(&(ht)->lock);
}

/* this inline is not really necessary, but it helps keep code consistent */
static inline void qht_unlock(struct qht *ht)
{
    qemu_mutex_unlock(&ht->lock);
}

/*
 * Note: reading partially-updated pointers in @pointers could lead to
 * segfaults. We thus access them with qatomic_read/set; this guarantees
 * that the compiler makes all those accesses atomic. We also need the
 * volatile-like behavior in qatomic_read, since otherwise the compiler
 * might refetch the pointer.
 * qatomic_read's are of course not necessary when the bucket lock is held.
 *
 * If both ht->lock and b->lock are grabbed, ht->lock should always
 * be grabbed first.
 */

// 一个hash桶中存多组[hash, pointer]
// 每一个qht_bucket都需要存各自的自旋锁和读写版本？还是说一个bucket里面的链表都统一
 struct qht_bucket {
    QemuSpin lock; 
    QemuSeqLock sequence; // 读写版本（lock-free优化？）
    // 这里hashes[QHT_BUCKET_ENTRIES]用的是数组，是为了加速cache命中，加速TB查询效率
    // 减少指针跳转带来的cache miss，如果不是数组，是单entry-每next一次都需要访存一次，一次访存预取整个 qht_bucket 常驻 L1 cache
    uint32_t hashes[QHT_BUCKET_ENTRIES]; // 每个entry的哈希值 一个entry就是一条记录条目-[hash, pointer]
    void *pointers[QHT_BUCKET_ENTRIES]; // TranslationBlock* 指针
    struct qht_bucket *next; // 链表指向下一个[hashes, pointers]
} QEMU_ALIGNED(QHT_BUCKET_ALIGN);

QEMU_BUILD_BUG_ON(sizeof(struct qht_bucket) > QHT_BUCKET_ALIGN);

/*
 * Under TSAN, we use striped locks instead of one lock per bucket chain.
 * This avoids crashing under TSAN, since TSAN aborts the program if more than
 * 64 locks are held (this is a hardcoded limit in TSAN).
 * When resizing a QHT we grab all the buckets' locks, which can easily
 * go over TSAN's limit. By using striped locks, we avoid this problem.
 *
 * Note: this number must be a power of two for easy index computation.
 */
#define QHT_TSAN_BUCKET_LOCKS_BITS 4
#define QHT_TSAN_BUCKET_LOCKS (1 << QHT_TSAN_BUCKET_LOCKS_BITS)

struct qht_tsan_lock {
    QemuSpin lock;
} QEMU_ALIGNED(QHT_BUCKET_ALIGN);

/**
 * struct qht_map - structure to track an array of buckets
 * @rcu: used by RCU. Keep it as the top field in the struct to help valgrind
 *       find the whole struct.
 * @buckets: array of head buckets. It is constant once the map is created.
 * @n_buckets: number of head buckets. It is constant once the map is created.
 * @n_added_buckets: number of added (i.e. "non-head") buckets
 * @n_added_buckets_threshold: threshold to trigger an upward resize once the
 *                             number of added buckets surpasses it.
 * @tsan_bucket_locks: Array of striped locks to be used only under TSAN.
 *
 * Buckets are tracked in what we call a "map", i.e. this structure.
 */
struct qht_map {
    struct rcu_head rcu; // 延迟销毁机制 
    struct qht_bucket *buckets; // 桶数组
    size_t n_buckets;  // 桶数量（总容量）
    size_t n_added_buckets; // 新增的bucket数量
    size_t n_added_buckets_threshold; // 扩容阈值
#ifdef CONFIG_TSAN
    struct qht_tsan_lock tsan_bucket_locks[QHT_TSAN_BUCKET_LOCKS];
#endif
};

/* trigger a resize when n_added_buckets > n_buckets / div */
#define QHT_NR_ADDED_BUCKETS_THRESHOLD_DIV 8

static void qht_do_resize_reset(struct qht *ht, struct qht_map *new,
                                bool reset);
static void qht_grow_maybe(struct qht *ht);

#ifdef QHT_DEBUG

#define qht_debug_assert(X) do { assert(X); } while (0)

static void qht_bucket_debug__locked(struct qht_bucket *b)
{
    bool seen_empty = false;
    bool corrupt = false;
    int i;

    do {
        for (i = 0; i < QHT_BUCKET_ENTRIES; i++) {
            if (b->pointers[i] == NULL) {
                seen_empty = true;
                continue;
            }
            if (seen_empty) {
                fprintf(stderr, "%s: b: %p, pos: %i, hash: 0x%x, p: %p\n",
                        __func__, b, i, b->hashes[i], b->pointers[i]);
                corrupt = true;
            }
        }
        b = b->next;
    } while (b);
    qht_debug_assert(!corrupt);
}

static void qht_map_debug__all_locked(struct qht_map *map)
{
    int i;

    for (i = 0; i < map->n_buckets; i++) {
        qht_bucket_debug__locked(&map->buckets[i]);
    }
}
#else

#define qht_debug_assert(X) do { (void)(X); } while (0)

static inline void qht_bucket_debug__locked(struct qht_bucket *b)
{ }

static inline void qht_map_debug__all_locked(struct qht_map *map)
{ }
#endif /* QHT_DEBUG */

static inline size_t qht_elems_to_buckets(size_t n_elems)
{
    return pow2ceil(n_elems / QHT_BUCKET_ENTRIES); // 2的幂次向上取整 —— 5->8  7->8 8->8 9->16
}

/*
 * When using striped locks (i.e. under TSAN), we have to be careful not
 * to operate on the same lock twice (e.g. when iterating through all buckets).
 * We achieve this by operating only on each stripe's first matching lock.
 */
static inline void qht_do_if_first_in_stripe(struct qht_map *map,
                                             struct qht_bucket *b,
                                             void (*func)(QemuSpin *spin))
{
#ifdef CONFIG_TSAN
    unsigned long bucket_idx = b - map->buckets;
    bool is_first_in_stripe = (bucket_idx >> QHT_TSAN_BUCKET_LOCKS_BITS) == 0;
    if (is_first_in_stripe) {
        unsigned long lock_idx = bucket_idx & (QHT_TSAN_BUCKET_LOCKS - 1);
        func(&map->tsan_bucket_locks[lock_idx].lock);
    }
#else
    func(&b->lock);
#endif
}

static inline void qht_bucket_lock_do(struct qht_map *map,
                                      struct qht_bucket *b,
                                      void (*func)(QemuSpin *lock))
{
#ifdef CONFIG_TSAN
    unsigned long bucket_idx = b - map->buckets;
    unsigned long lock_idx = bucket_idx & (QHT_TSAN_BUCKET_LOCKS - 1);
    func(&map->tsan_bucket_locks[lock_idx].lock);
#else
    func(&b->lock);
#endif
}

static inline void qht_bucket_lock(struct qht_map *map,
                                   struct qht_bucket *b)
{
    qht_bucket_lock_do(map, b, qemu_spin_lock);
}

static inline void qht_bucket_unlock(struct qht_map *map,
                                     struct qht_bucket *b)
{
    qht_bucket_lock_do(map, b, qemu_spin_unlock);
}

static inline void qht_head_init(struct qht_map *map, struct qht_bucket *b)
{
    memset(b, 0, sizeof(*b));
    qht_do_if_first_in_stripe(map, b, qemu_spin_init);
    seqlock_init(&b->sequence);
}

static inline
struct qht_bucket *qht_map_to_bucket(const struct qht_map *map, uint32_t hash)
{
    return &map->buckets[hash & (map->n_buckets - 1)];
}

/* acquire all bucket locks from a map */
static void qht_map_lock_buckets(struct qht_map *map)
{
    size_t i;

    for (i = 0; i < map->n_buckets; i++) {
        struct qht_bucket *b = &map->buckets[i];

        qht_do_if_first_in_stripe(map, b, qemu_spin_lock);
    }
}

static void qht_map_unlock_buckets(struct qht_map *map)
{
    size_t i;

    for (i = 0; i < map->n_buckets; i++) {
        struct qht_bucket *b = &map->buckets[i];

        qht_do_if_first_in_stripe(map, b, qemu_spin_unlock);
    }
}

/*
 * Call with at least a bucket lock held.
 * @map should be the value read before acquiring the lock (or locks).
 */
static inline bool qht_map_is_stale__locked(const struct qht *ht,
                                            const struct qht_map *map)
{
    return map != ht->map;
}

/*
 * Grab all bucket locks, and set @pmap after making sure the map isn't stale.
 *
 * Pairs with qht_map_unlock_buckets(), hence the pass-by-reference.
 *
 * Note: callers cannot have ht->lock held.
 */
static inline
void qht_map_lock_buckets__no_stale(struct qht *ht, struct qht_map **pmap)
{
    struct qht_map *map;

    map = qatomic_rcu_read(&ht->map);
    qht_map_lock_buckets(map);
    if (likely(!qht_map_is_stale__locked(ht, map))) {
        *pmap = map;
        return;
    }
    qht_map_unlock_buckets(map);

    /* we raced with a resize; acquire ht->lock to see the updated ht->map */
    qht_lock(ht);
    map = ht->map;
    qht_map_lock_buckets(map);
    qht_unlock(ht);
    *pmap = map;
    return;
}

/*
 * Get a head bucket and lock it, making sure its parent map is not stale.
 * @pmap is filled with a pointer to the bucket's parent map.
 *
 * Unlock with qht_bucket_unlock.
 *
 * Note: callers cannot have ht->lock held.
 */
static inline
struct qht_bucket *qht_bucket_lock__no_stale(struct qht *ht, uint32_t hash,
                                             struct qht_map **pmap)
{
    struct qht_bucket *b;
    struct qht_map *map;

    map = qatomic_rcu_read(&ht->map); // 提取tcg_ctx.htable中提取map
    b = qht_map_to_bucket(map, hash); // 获取tb-hash所在bucket

    qht_bucket_lock(map, b); // 对该bucket加锁
    if (likely(!qht_map_is_stale__locked(ht, map))) { // 提取的 map 和当前 ht.map 是否相同-是否是最新的
        *pmap = map; // map是否相等->本质就是是否扩容，如果扩容，地址不同，如果没有扩容，地址相同，则会返回bucket，获取map
        return b;
    }
    qht_bucket_unlock(map, b);
    // 到了这里，说明进行了扩容，ht.map和map地址不同
    /* we raced with a resize; acquire ht->lock to see the updated ht->map */
    qht_lock(ht); // 全局锁，保证获取最新的map
    map = ht->map; // 获取最新的map、bucket
    b = qht_map_to_bucket(map, hash);
    qht_bucket_lock(map, b); // 加锁新桶
    qht_unlock(ht); // 释放全局锁
    *pmap = map;
    return b; // 返回bucket和map
}

static inline bool qht_map_needs_resize(const struct qht_map *map)
{
    return qatomic_read(&map->n_added_buckets) >
           map->n_added_buckets_threshold; // 超过阈值 - true - 需要扩容
}

static inline void qht_chain_destroy(struct qht_map *map,
                                     struct qht_bucket *head)
{
    struct qht_bucket *curr = head->next;
    struct qht_bucket *prev;

    qht_do_if_first_in_stripe(map, head, qemu_spin_destroy);
    while (curr) {
        prev = curr;
        curr = curr->next;
        qemu_vfree(prev);
    }
}

/* pass only an orphan map */
static void qht_map_destroy(struct qht_map *map)
{
    size_t i;

    for (i = 0; i < map->n_buckets; i++) {
        qht_chain_destroy(map, &map->buckets[i]);
    }
    qemu_vfree(map->buckets);
    g_free(map);
}

static struct qht_map *qht_map_create(size_t n_buckets)
{
    struct qht_map *map;
    size_t i;
    // malloc、设置初始值
    map = g_malloc(sizeof(*map));
    map->n_buckets = n_buckets;

    map->n_added_buckets = 0;
    map->n_added_buckets_threshold = n_buckets /
        QHT_NR_ADDED_BUCKETS_THRESHOLD_DIV;

    /* let tiny hash tables to at least add one non-head bucket */
    if (unlikely(map->n_added_buckets_threshold == 0)) {
        map->n_added_buckets_threshold = 1;
    }

    map->buckets = qemu_memalign(QHT_BUCKET_ALIGN,
                                 sizeof(*map->buckets) * n_buckets); // 每个bucket包含四个entry next指针...
    for (i = 0; i < n_buckets; i++) {
        qht_head_init(map, &map->buckets[i]); // 初始化所有bucket
    }
    return map;
}

void qht_init(struct qht *ht, qht_cmp_func_t cmp, size_t n_elems,
              unsigned int mode)
{
    struct qht_map *map;
    size_t n_buckets = qht_elems_to_buckets(n_elems); // 向上去二的幂次

    g_assert(cmp);
    ht->cmp = cmp;
    ht->mode = mode;
    qemu_mutex_init(&ht->lock);
    map = qht_map_create(n_buckets); // 桶的个数-n_buckets
    qatomic_rcu_set(&ht->map, map);
}

/* call only when there are no readers/writers left */
void qht_destroy(struct qht *ht)
{
    qht_map_destroy(ht->map);
    memset(ht, 0, sizeof(*ht));
}

static void qht_bucket_reset__locked(struct qht_bucket *head)
{ // 桶内遍历每一个b->hashes[i] b->pointers[i] 设置为[0, null] 
// 注意，这里会把一个桶内的数组，以及next到下一个bucket进行清空，也就是把链表都清空 O(4k)
    struct qht_bucket *b = head;
    int i;

    seqlock_write_begin(&head->sequence);
    do {
        for (i = 0; i < QHT_BUCKET_ENTRIES; i++) {
            if (b->pointers[i] == NULL) {
                goto done;
            }
            qatomic_set(&b->hashes[i], 0);
            qatomic_set(&b->pointers[i], NULL);
        }
        b = b->next;
    } while (b);
 done:
    seqlock_write_end(&head->sequence);
}

/* call with all bucket locks held */
static void qht_map_reset__all_locked(struct qht_map *map)
{
    size_t i;

    for (i = 0; i < map->n_buckets; i++) { // 遍历每一个桶
        qht_bucket_reset__locked(&map->buckets[i]);
    }
    qht_map_debug__all_locked(map);
}

void qht_reset(struct qht *ht)
{
    struct qht_map *map;

    qht_map_lock_buckets__no_stale(ht, &map);
    qht_map_reset__all_locked(map);
    qht_map_unlock_buckets(map);
}

static inline void qht_do_resize(struct qht *ht, struct qht_map *new)
{
    qht_do_resize_reset(ht, new, false);
}

static inline void qht_do_resize_and_reset(struct qht *ht, struct qht_map *new)
{
    qht_do_resize_reset(ht, new, true); // reset默认为true
}

bool qht_reset_size(struct qht *ht, size_t n_elems) // n_elems是期望容量
{
    struct qht_map *new = NULL;
    struct qht_map *map;
    size_t n_buckets;

    n_buckets = qht_elems_to_buckets(n_elems); // 这里相当于得到了一个默认的桶数量 n_buckets = n_elems/QHT_BUCKET_ENTRIES 二次幂取整

    qht_lock(ht);
    map = ht->map;
    if (n_buckets != map->n_buckets) { // 当前的map和默认的不相同，malloc以n_buckets为大小的qht_map -resize
        new = qht_map_create(n_buckets); // 分配空间、初始化、桶内数组分配空间
    }
    qht_do_resize_and_reset(ht, new); // 核心
    qht_unlock(ht);

    return !!new;
}

static inline
void *qht_do_lookup(const struct qht_bucket *head, qht_lookup_func_t func,
                    const void *userp, uint32_t hash)
{
    const struct qht_bucket *b = head;
    int i;

    do {
        for (i = 0; i < QHT_BUCKET_ENTRIES; i++) {
            if (qatomic_read(&b->hashes[i]) == hash) { // hash真正匹配到了，就去用func回调判断主哈希表中的TB的字段和当前的描述符的字段是否相同
                /* The pointer is dereferenced before seqlock_read_retry,
                 * so (unlike qht_insert__locked) we need to use
                 * qatomic_rcu_read here.
                 */
                void *p = qatomic_rcu_read(&b->pointers[i]);

                if (likely(p) && likely(func(p, userp))) { // func(TB, desc)
                    return p;
                }
            }
        }
        b = qatomic_rcu_read(&b->next);
    } while (b);

    return NULL;
}

static __attribute__((noinline))
void *qht_lookup__slowpath(const struct qht_bucket *b, qht_lookup_func_t func,
                           const void *userp, uint32_t hash)
{
    unsigned int version;
    void *ret;

    do {
        version = seqlock_read_begin(&b->sequence);
        ret = qht_do_lookup(b, func, userp, hash);
    } while (seqlock_read_retry(&b->sequence, version));
    return ret;
}

void *qht_lookup_custom(const struct qht *ht, const void *userp, uint32_t hash,
                        qht_lookup_func_t func)
{
    const struct qht_bucket *b;
    const struct qht_map *map; 
    unsigned int version;
    void *ret;
    // map中存储了所有桶，桶之间用链表链接（next指针）
    map = qatomic_rcu_read(&ht->map);
    // 通过hash提取具体的某个桶，一个桶中多个[hash, pointer]结构
    // hash=72  75/8=9  77/8=9 所以75和77号hash都放在9号桶中，所以后续还需要通过hash定位具体是否有相等的[hash, pointer]
    b = qht_map_to_bucket(map, hash);

    version = seqlock_read_begin(&b->sequence);
    // 遍历桶内value，哈希值匹配时使用回调函数，匹配desc描述符字段是否相等
    ret = qht_do_lookup(b, func, userp, hash); 
    if (likely(!seqlock_read_retry(&b->sequence, version))) {
        return ret;
    }
    /*
     * Removing the do/while from the fastpath gives a 4% perf. increase when
     * running a 100%-lookup microbenchmark.
     */
    return qht_lookup__slowpath(b, func, userp, hash);
}

void *qht_lookup(const struct qht *ht, const void *userp, uint32_t hash)
{
    return qht_lookup_custom(ht, userp, hash, ht->cmp);
}

/*
 * call with head->lock held
 * @ht is const since it is only used for ht->cmp()
 */ // 哈希表管理ht，当前的map，head是该hash的主桶，p是当前的tb，本次的hash值，是否扩容needs_resize-默认false
static void *qht_insert__locked(const struct qht *ht, struct qht_map *map,
                                struct qht_bucket *head, void *p, uint32_t hash,
                                bool *needs_resize)
{
    struct qht_bucket *b = head;
    struct qht_bucket *prev = NULL;
    struct qht_bucket *new = NULL;
    int i;

    do {
        for (i = 0; i < QHT_BUCKET_ENTRIES; i++) { // 遍历桶中数组查找是否已存在当前tb（p）
            if (b->pointers[i]) { // 是否存在
                if (unlikely(b->hashes[i] == hash &&
                             ht->cmp(b->pointers[i], p))) {
                    return b->pointers[i]; // 查找到，直接返回该tb
                }
            } else {
                goto found; // 不存在-找到空位
            }
        }
        prev = b; // 这一轮for循环完以后，把bucket存入prev
        b = b->next; // 下一个qht_bucket桶中寻找，直到不存在去到goto或者桶中数组满，去开辟新bucket
    } while (b);
    // 分配新的桶的空间并初始化
    b = qemu_memalign(QHT_BUCKET_ALIGN, sizeof(*b)); // 分配对齐的内存块，分配大小是sizeof(*b)
    memset(b, 0, sizeof(*b)); // 初始化新分配的桶
    new = b; // 新的桶设置为new
    i = 0;
    qatomic_inc(&map->n_added_buckets); // 创建新的bucket - n_added_buckets++ 原子加-increment
    // map->n_added_buckets > map->n_added_buckets_threshold - true - 需要扩容
    // 这里needs_resize是地址，地址不为NULL即可
    if (unlikely(qht_map_needs_resize(map)) && needs_resize) { 
        *needs_resize = true; // needs_resize会作为需要扩容的标志
    }
    
 found:
    /* found an empty key: acquire the seqlock and write */
    seqlock_write_begin(&head->sequence); // 写屏蔽
    if (new) { // 这里new更多作为标志位，其来源为new = b，以及对于got found路径来说，就没有创建新的bucket，不能prev->next = b
        qatomic_rcu_set(&prev->next, b); // prev->next = b b是当前桶
    }
    /* smp_wmb() implicit in seqlock_write_begin.  */
    qatomic_set(&b->hashes[i], hash); // b_>hashes[i] = hash 新开辟后插入hash tb
    qatomic_set(&b->pointers[i], p); //  b->pointers[i] = p
    seqlock_write_end(&head->sequence);
    return NULL;
}

static __attribute__((noinline)) void qht_grow_maybe(struct qht *ht)
{
    struct qht_map *map;

    /*
     * If the lock is taken it probably means there's an ongoing resize,
     * so bail out.
     */
    if (qht_trylock(ht)) { // 尝试锁，返回0说明其他线程正在扩容
        return;
    }
    map = ht->map;
    /* another thread might have just performed the resize we were after */
    if (qht_map_needs_resize(map)) { // 新增的桶的数量是否超过阈值（链式过多-负载过高）超过阈值需要扩容是一种建议性质的，也就是从性能角度建议扩容
        struct qht_map *new = qht_map_create(map->n_buckets * 2); // 当前桶的数量乘以2倍
        qht_do_resize(ht, new); // 扩容过程-原表数据迁移到新表上
    }
    qht_unlock(ht); // 释放哈希表锁
}

bool qht_insert(struct qht *ht, void *p, uint32_t hash, void **existing)
{
    struct qht_bucket *b;
    struct qht_map *map;
    bool needs_resize = false;
    void *prev;

    /* NULL pointers are not supported */
    qht_debug_assert(p);

    b = qht_bucket_lock__no_stale(ht, hash, &map); // 通过hash获取bucket并给桶加锁
     // 插入逻辑，prev要么是找到的tb，要么是插入成功返回null，needs_resize标志位是否需要扩容
    prev = qht_insert__locked(ht, map, b, p, hash, &needs_resize);
    qht_bucket_debug__locked(b);
    qht_bucket_unlock(map, b); // 解锁

    // ht->mode 和 QHT_MODE_AUTO_RESIZE是运行时配置
    // 1、正在做性能测试，想要固定容量
    // 2、某些嵌入式环境要求内存使用严格受控
    // 3、某些调试场景我们想显式控制resize时机
    // ... ...
    if (unlikely(needs_resize) && ht->mode & QHT_MODE_AUTO_RESIZE) { 
        qht_grow_maybe(ht); // 扩容 old_map 迁移到 new_map
    }
    if (likely(prev == NULL)) {
        return true; // prev为NULL，插入成功
    }
    if (existing) {
        *existing = prev; // prev存在说明表中已有，那么existing赋值为prev
    }
    return false;
}

static inline bool qht_entry_is_last(const struct qht_bucket *b, int pos)
{
    if (pos == QHT_BUCKET_ENTRIES - 1) {
        if (b->next == NULL) {
            return true;
        }
        return b->next->pointers[0] == NULL;// 一个空的bucket挂在next上，也说明是最后一个tb
    }
    return b->pointers[pos + 1] == NULL; // 不是bucket数组最后一个，那么只有在该数组中下一个tb为空时是最后一个tb
}

static void
qht_entry_move(struct qht_bucket *to, int i, struct qht_bucket *from, int j)
{
    qht_debug_assert(!(to == from && i == j));
    qht_debug_assert(to->pointers[i]);
    qht_debug_assert(from->pointers[j]);

    qatomic_set(&to->hashes[i], from->hashes[j]);
    qatomic_set(&to->pointers[i], from->pointers[j]);

    qatomic_set(&from->hashes[j], 0);
    qatomic_set(&from->pointers[j], NULL);
}

/*
 * Find the last valid entry in @orig, and swap it with @orig[pos], which has
 * just been invalidated.
 */
static inline void qht_bucket_remove_entry(struct qht_bucket *orig, int pos)
{
    struct qht_bucket *b = orig;
    struct qht_bucket *prev = NULL;
    int i;
    // 为了保证tb排布紧密，所以需要判断remove的tb是否是最后一个
    if (qht_entry_is_last(orig, pos)) {
        qatomic_set(&orig->hashes[pos], 0);// 是最后一个
        qatomic_set(&orig->pointers[pos], NULL);
        return;
    }
    do {
        for (i = 0; i < QHT_BUCKET_ENTRIES; i++) {
            if (b->pointers[i]) {
                continue;
            }
            if (i > 0) {
                return qht_entry_move(orig, pos, b, i - 1);
            }
            qht_debug_assert(prev);
            return qht_entry_move(orig, pos, prev, QHT_BUCKET_ENTRIES - 1);
        }
        prev = b;
        b = b->next;
    } while (b);
    /* no free entries other than orig[pos], so swap it with the last one */
    qht_entry_move(orig, pos, prev, QHT_BUCKET_ENTRIES - 1);
}

/* call with b->lock held */
static inline
bool qht_remove__locked(struct qht_bucket *head, const void *p, uint32_t hash)
{
    struct qht_bucket *b = head;
    int i;

    do {
        for (i = 0; i < QHT_BUCKET_ENTRIES; i++) {
            void *q = b->pointers[i];

            if (unlikely(q == NULL)) {
                return false;
            }
            if (q == p) {
                qht_debug_assert(b->hashes[i] == hash);
                seqlock_write_begin(&head->sequence);
                qht_bucket_remove_entry(b, i);
                seqlock_write_end(&head->sequence);
                return true;
            }
        }
        b = b->next;
    } while (b);
    return false;
}

bool qht_remove(struct qht *ht, const void *p, uint32_t hash)
{
    struct qht_bucket *b;
    struct qht_map *map;
    bool ret;

    /* NULL pointers are not supported */
    qht_debug_assert(p);

    b = qht_bucket_lock__no_stale(ht, hash, &map); // 获取hash值并加锁
    ret = qht_remove__locked(b, p, hash);
    qht_bucket_debug__locked(b);
    qht_bucket_unlock(map, b);
    return ret;
}
// 处理一个桶以及next桶
static inline void qht_bucket_iter(struct qht_bucket *head,
                                   const struct qht_iter *iter, void *userp)
{
    struct qht_bucket *b = head;
    int i;

    do {
        for (i = 0; i < QHT_BUCKET_ENTRIES; i++) { // 单个桶内遍历，这里是遍历桶内数组长度
            if (b->pointers[i] == NULL) { // 遍历的tb为空，结束遍历 （tb是密排无空隙）
                return;
            }
            switch (iter->type) {
            case QHT_ITER_VOID: // 访问模式
                iter->f.retvoid(b->pointers[i], b->hashes[i], userp); // 把旧的tb插入新的tb中 - 迁移
                break;
            case QHT_ITER_RM:   // 删除模式
                if (iter->f.retbool(b->pointers[i], b->hashes[i], userp)) {
                    /* replace i with the last valid element in the bucket */
                    seqlock_write_begin(&head->sequence);
                    qht_bucket_remove_entry(b, i);
                    seqlock_write_end(&head->sequence);
                    qht_bucket_debug__locked(b);
                    /* reevaluate i, since it just got replaced */
                    i--;
                    continue;
                }
                break;
            default:
                g_assert_not_reached();
            }
        }
        b = b->next; // 链式
    } while (b);
}

/* call with all of the map's locks held */
static inline void qht_map_iter__all_locked(struct qht_map *map,
                                            const struct qht_iter *iter,
                                            void *userp)
{
    size_t i;

    for (i = 0; i < map->n_buckets; i++) { // 遍历哈希桶[0, 8191]
        qht_bucket_iter(&map->buckets[i], iter, userp);
    }
}

static inline void
do_qht_iter(struct qht *ht, const struct qht_iter *iter, void *userp)
{
    struct qht_map *map;

    map = qatomic_rcu_read(&ht->map);
    qht_map_lock_buckets(map);
    qht_map_iter__all_locked(map, iter, userp);
    qht_map_unlock_buckets(map);
}

void qht_iter(struct qht *ht, qht_iter_func_t func, void *userp)
{
    const struct qht_iter iter = {
        .f.retvoid = func,
        .type = QHT_ITER_VOID,
    };

    do_qht_iter(ht, &iter, userp);
}

void qht_iter_remove(struct qht *ht, qht_iter_bool_func_t func, void *userp)
{
    const struct qht_iter iter = {
        .f.retbool = func,
        .type = QHT_ITER_RM,
    };

    do_qht_iter(ht, &iter, userp);
}

struct qht_map_copy_data {
    struct qht *ht;
    struct qht_map *new;
};

static void qht_map_copy(void *p, uint32_t hash, void *userp)
{
    struct qht_map_copy_data *data = userp;
    struct qht *ht = data->ht;
    struct qht_map *new = data->new;
    struct qht_bucket *b = qht_map_to_bucket(new, hash); // 根据hash找到新的桶的位置

    /* no need to acquire b->lock because no thread has seen this map yet */
    qht_insert__locked(ht, new, b, p, hash, NULL); // 将tb（p）插入到新的哈希桶中，插入操作是紧密排布的[0~3] next ...
}

/*
 * Atomically perform a resize and/or reset.
 * Call with ht->lock held.
 */  // 原子的替换主表/清空现有数据，这里的原子说的是该操作是一个整体，不可分割
static void qht_do_resize_reset(struct qht *ht, struct qht_map *new, bool reset) 
{
    struct qht_map *old;
    const struct qht_iter iter = {
        .f.retvoid = qht_map_copy,
        .type = QHT_ITER_VOID,
    };
    struct qht_map_copy_data data; // data中包含了[qht ht, qht_map new]
    old = ht->map;
    qht_map_lock_buckets(old); // 锁住

    if (reset) { // reset默认为true
        qht_map_reset__all_locked(old); // 清空旧表
    }

    if (new == NULL) {
        qht_map_unlock_buckets(old); // new == null 说明只经历reset清空，不需要resize，直接结束，不需要替换ht->map为new
        return;
    }
    // 到了这里，说明new非空，需要替换ht->map
    g_assert(new->n_buckets != old->n_buckets);
    data.ht = ht;
    data.new = new; // new是新的空的表
    // 对于reset == true new != null的情况，到这里里面会直接return，不会进行拷贝
    // 这里的qht_map_iter__all_locked函数应该是为了更加通用做的
    qht_map_iter__all_locked(old, &iter, &data);
    qht_map_debug__all_locked(new);

    qatomic_rcu_set(&ht->map, new); // 替换ht->map = new
    qht_map_unlock_buckets(old); // 解锁
    call_rcu(old, qht_map_destroy, rcu);
}

bool qht_resize(struct qht *ht, size_t n_elems)
{
    size_t n_buckets = qht_elems_to_buckets(n_elems);
    size_t ret = false;

    qht_lock(ht);
    if (n_buckets != ht->map->n_buckets) {
        struct qht_map *new;

        new = qht_map_create(n_buckets);
        qht_do_resize(ht, new);
        ret = true;
    }
    qht_unlock(ht);

    return ret;
}

/* pass @stats to qht_statistics_destroy() when done */
void qht_statistics_init(const struct qht *ht, struct qht_stats *stats)
{
    const struct qht_map *map;
    int i;

    map = qatomic_rcu_read(&ht->map);

    stats->used_head_buckets = 0;
    stats->entries = 0;
    qdist_init(&stats->chain);
    qdist_init(&stats->occupancy);
    /* bail out if the qht has not yet been initialized */
    if (unlikely(map == NULL)) {
        stats->head_buckets = 0;
        return;
    }
    stats->head_buckets = map->n_buckets;

    for (i = 0; i < map->n_buckets; i++) {
        const struct qht_bucket *head = &map->buckets[i];
        const struct qht_bucket *b;
        unsigned int version;
        size_t buckets;
        size_t entries;
        int j;

        do {
            version = seqlock_read_begin(&head->sequence);
            buckets = 0;
            entries = 0;
            b = head;
            do {
                for (j = 0; j < QHT_BUCKET_ENTRIES; j++) {
                    if (qatomic_read(&b->pointers[j]) == NULL) {
                        break;
                    }
                    entries++;
                }
                buckets++;
                b = qatomic_rcu_read(&b->next);
            } while (b);
        } while (seqlock_read_retry(&head->sequence, version));

        if (entries) {
            qdist_inc(&stats->chain, buckets);
            qdist_inc(&stats->occupancy,
                      (double)entries / QHT_BUCKET_ENTRIES / buckets);
            stats->used_head_buckets++;
            stats->entries += entries;
        } else {
            qdist_inc(&stats->occupancy, 0);
        }
    }
}

void qht_statistics_destroy(struct qht_stats *stats)
{
    qdist_destroy(&stats->occupancy);
    qdist_destroy(&stats->chain);
}
