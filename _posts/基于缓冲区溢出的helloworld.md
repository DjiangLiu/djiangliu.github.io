


```
#include <stdio.h>

void fn()
{
	int i;
	int arr[5] = { 0 };
	for (size_t i = 0; i <= 5; i++)
	{
		arr[i] = 0;
		printf("hello world\n");
	}
}

void HelloWorld()
{
	printf("Hello World");
	getchar();
}

void func()
{
	int arr[5] = { 1,2,3,4,5 };
	arr[6] = (int)HelloWorld;
}


void main(void)
{
	//fn();
	func();
}
```



局部变量初始值是 cc
类型转换
	