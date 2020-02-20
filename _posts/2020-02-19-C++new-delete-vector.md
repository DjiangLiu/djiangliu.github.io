---
title: C++友元函数和运算符重载
date: 2020-2-19
categories: 
- C++
tags: 
- new
- delete
- vector
---

# 向量Vector特点
1. 数组：可以在栈上，可以在全局变量，也可以malloc（堆）。在全局变量和栈上不需要释放。malloc free 成对出现



# vector实现
# new delete本质
## malloc实现过程

1. malloc


```c
FF call的是IAT表0042a1e4里面的值

malloc  ->  _nh_malloc_dbg  ->  _heap_alloc_dbg ->  _heap_alloc_base    ->  HeapAlloc

  0040B90C FF 15 E4 A1 42 00    call        dword ptr [__imp__HeapAlloc@12 (0042a1e4)]
``` 

2. free。free过程中memset一次。

```c
free    _free_dbg   _free_base    HeapFree  
0040BF8B FF 15 B8 A1 42 00    call        dword ptr [__imp__HeapFree@12 (0042a1b8)]
```

3. new的本质和malloc一样

```c
new _nh_malloc  _nh_malloc_dbg  
```

4. delete的本质和free一样

```c
delete  _free_dbg
```

## new本质

```c
	//创建一个int大小的堆空间
	int* pi = new int;
	//创建一个int并且初始值是5
	int* pk = new int(5);
    
    int* i = new int[5];//创建5个int空间
	delete[] i;
	
    delete pi;
	delete pk;

    Person* p3 = new Person[5];
	delete[] p3;
```

```c
#include<stdio.h>
#include<malloc.h>

class Person
{
private:
	int x;
	int y;
public:
	Person()
	{

	}
	Person(int x, int y)
	{
		this->x = x;
		this->y = y;
	}
};

int main(void)
{
	Person* p1 = new Person;//new Person()
	Person* p2 = new Person(1, 2);
}
```