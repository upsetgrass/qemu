#include<stdio.h>

int main()
{
	for(int i = 0; i < 100000;i++ )
	{
		if(i % 5000 == 999)
		{
			printf("i = %d\n", i);
		}
	}
	printf("finish!\n");
	return 0;
}
