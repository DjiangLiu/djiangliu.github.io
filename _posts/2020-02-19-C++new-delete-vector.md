---
title: 数据结构-vector
date: 2020-2-19
categories: 
- C++
tags: 
- new
- delete
- vector
- 数据结构
---

# 向量Vector特点
1. 数组：可以在栈上，可以在全局变量，也可以malloc（堆）。在全局变量和栈上不需要释放。malloc free 成对出现

## 本质

1. 一个数组
2. 可以动态扩容
3. 支持下标，查询性能好。（连续）
4. 新增数据和删除数据较差


## vector实现

```c
#define VSUCCESS                        1 // 成功        
#define VERROR                         -1 // 失败        
#define MALLOC_ERROR             -2 // 申请内存失败        
#define INDEX_ERROR              -3 // 错误的索引号

#include "stdio.h"
#include <stdlib.h>
#include <windows.h>

template <class T_ELE>
class Vector
{
public:
    Vector();
    Vector(DWORD dwSize);
    ~Vector();
public:
    DWORD    at(DWORD dwIndex, OUT T_ELE* pEle);                    //根据给定的索引得到元素                
    DWORD    push_back(T_ELE Element);                        //将元素存储到容器最后一个位置                
    VOID    pop_back();                    //删除最后一个元素                
    DWORD    insert(DWORD dwIndex, T_ELE Element);                    //向指定位置新增一个元素                
    DWORD    capacity();                    //返回在不增容的情况下，还能存储多少元素                
    VOID    clear();                    //清空所有元素                
    BOOL    empty();                    //判断Vector是否为空 返回true时为空                
    VOID    erase(DWORD dwIndex);                    //删除指定元素                
    DWORD    size();                    //返回Vector元素数量的大小                
private:
    BOOL    expand();
private:
    DWORD  m_dwIndex;                        //下一个可用索引                
    DWORD  m_dwIncrement;                        //每次增容的大小                
    DWORD  m_dwLen;                        //当前容器的长度                
    DWORD  m_dwInitSize;                        //默认初始化大小                
    T_ELE* m_pVector;                        //容器指针                
};

//********无参构造**********
template <class T_ELE>
Vector<T_ELE>::Vector()
    :m_dwInitSize(100), m_dwIncrement(5)
{
    //1.创建长度为m_dwInitSize个T_ELE对象
    m_pVector = new T_ELE[m_dwInitSize];

    //2.将新创建的空间初始化                                        
    memset(m_pVector, 0, sizeof(T_ELE) * m_dwInitSize);

    //3.设置其他值
    m_dwIndex = 0;
    m_dwLen = m_dwInitSize;
}

//************有参构造*************                                        
template <class T_ELE>
Vector<T_ELE>::Vector(DWORD dwSize)
    :m_dwIncrement(5)
{
    //1.创建长度为dwSize个T_ELE对象    
    m_pVector = new T_ELE[dwSize];
    if (!m_pVector) {
        return;
    }

    //2.将新创建的空间初始化                                        
    memset(m_pVector, 0, sizeof(T_ELE) * dwSize);


    //3.设置其他值    
    m_dwIndex = 0;
    m_dwLen = dwSize;

}

//************析构函数*************                                        
template <class T_ELE>
Vector<T_ELE>::~Vector()
{
    //释放空间 delete[]    
    delete[] m_pVector;


}

//************扩容*************                                                
template <class T_ELE>
BOOL Vector<T_ELE>::expand()
{
    // 1. 计算增加后的长度                                        
    DWORD size = m_dwLen + m_dwIncrement;
    printf("数组容量%d不够，扩容为%d\n", m_dwLen, size);
    // 2. 申请空间                                        
    T_ELE* newArr = new T_ELE[size];
    if (!newArr) {
        return FALSE;
    }

    // 3. 将数据复制到新的空间
    memset(newArr, 0, sizeof(T_ELE) * size);
    memcpy(newArr, m_pVector, sizeof(T_ELE) * m_dwLen);

    // 4. 释放原来空间                                        
    delete[] m_pVector;
    m_pVector = newArr;
    newArr = NULL;

    // 5. 为各种属性赋值                                        
    m_dwLen = size;


    return TRUE;
}

//************末尾添加*************                                                
template <class T_ELE>
DWORD  Vector<T_ELE>::push_back(T_ELE Element)
{
    //1.判断是否需要增容，如果需要就调用增容的函数
    if (m_dwIndex >= m_dwLen) {
        expand();
    }

    //2.将新的元素复制到容器的最后一个位置
    m_pVector[m_dwIndex] = Element;

    //3.修改属性值                                        
    m_dwIndex++;
    return VSUCCESS;
}

//************中间插入*************                                                
template <class T_ELE>
DWORD  Vector<T_ELE>::insert(DWORD dwIndex, T_ELE Element)
{
    //1.判断是否需要增容，如果需要就调用增容的函数                                        
    if (m_dwIndex >= m_dwLen) {
        expand();
    }

    //2.判断索引是否在合理区间                                        
    if (dwIndex<0 || dwIndex>m_dwIndex) {
        return INDEX_ERROR;
    }

    //3.将dwIndex只后的元素后移                                        
    for (int i = m_dwIndex; i > dwIndex; i--) {
        memcpy(m_pVector + i, m_pVector + i - 1, sizeof(T_ELE));
    }

    //4.将Element元素复制到dwIndex位置                                        
    memcpy(m_pVector + dwIndex, &Element, sizeof(T_ELE));

    //5.修改属性值
    m_dwIndex++;
    return VSUCCESS;
}

//************下标获取*************                                            
template <class T_ELE>
DWORD Vector<T_ELE>::at(DWORD dwIndex, T_ELE* pEle)
{
    //判断索引是否在合理区间                                        
    if (dwIndex < 0 || dwIndex >= m_dwIndex) {
        return INDEX_ERROR;
    }

    //将dwIndex的值复制到pEle指定的内存                                        
    memcpy(pEle, m_pVector + dwIndex, sizeof(T_ELE));
    return VSUCCESS;
}

//********末尾删除***********
template <class T_ELE>
VOID Vector<T_ELE>::pop_back() {
    //判断是否还有
    if (m_dwLen <= 0) {
        printf("一个元素都没有了\n");
        return;
    }
    //删除
    m_dwIndex--;
    memset(m_pVector + m_dwIndex, 0, sizeof(T_ELE));
}

//********不增容剩余容量********
template <class T_ELE>
DWORD Vector<T_ELE>::capacity() {
    return m_dwLen - m_dwIndex;
}

//*********清空容器*******
template <class T_ELE>
VOID Vector<T_ELE>::clear() {
    memset(m_pVector, 0, sizeof(T_ELE) * (m_dwIndex + 1));
    //修改属性值
    m_dwIndex = 0;
}

//**********判断容器是否为空******
template <class T_ELE>
BOOL Vector<T_ELE>::empty() {
    if (m_pVector) {
        return TRUE;
    }
    else {
        return FALSE;
    }
}

//*********删除指定元素********
template <class T_ELE>
VOID Vector<T_ELE>::erase(DWORD dwIndex) {
    //判断下标是否在有效区间
    if (dwIndex<0 || dwIndex >m_dwIndex) {
        printf("下标越界了\n");
        return;
    }
    //删除
    for (int i = dwIndex; i < m_dwIndex; i++) {
        memcpy(m_pVector + i, m_pVector + i + 1, sizeof(T_ELE));
    }
    m_dwIndex--;
    memset(m_pVector + m_dwIndex, 0, sizeof(T_ELE));

}

//********返回元素数量*******
template <class T_ELE>
DWORD Vector<T_ELE>::size() {
    return m_dwIndex;
}

template <class T_ELE>
void printVector(Vector<T_ELE>* list) {
    for (int i = 0; i < list->size(); i++) {
        T_ELE k;
        list->at(i, &k);
        printf("%d\t", k);
    }
    printf("\n");
}

void main() {
    Vector<int>* list = new Vector<int>(5);

    list->push_back(1);
    list->push_back(2);
    list->push_back(3);
    list->push_back(4);
    printVector(list);
    printf("元素个数：%d,容量还剩%d\n", list->size(), list->capacity());

    list->insert(2, 12);
    printVector(list);
    printf("元素个数：%d,容量还剩%d\n", list->size(), list->capacity());

    list->push_back(5);
    list->push_back(6);
    list->push_back(7);
    printVector(list);
    printf("元素个数：%d,容量还剩%d\n", list->size(), list->capacity());

    list->pop_back();
    list->erase(0);
    printVector(list);
    printf("元素个数：%d,容量还剩%d\n", list->size(), list->capacity());

    list->clear();
    printVector(list);
    printf("元素个数：%d,容量还剩%d\n", list->size(), list->capacity());

    getchar();
}
```

```c

#pragma once

#define VSUCCESS                        1 // 成功        
#define VERROR                         -1 // 失败        
#define MALLOC_ERROR             -2 // 申请内存失败        
#define INDEX_ERROR              -3 // 错误的索引号

#include <stdlib.h>
#include <windows.h>

template <class T_ELE>
class Vector
{
public:
    Vector();
    Vector(DWORD dwSize);
    ~Vector();
public:
    DWORD    at(DWORD dwIndex, OUT T_ELE* pEle);                    //根据给定的索引得到元素                
    DWORD    push_back(T_ELE Element);                        //将元素存储到容器最后一个位置                
    VOID    pop_back();                    //删除最后一个元素                
    DWORD    insert(DWORD dwIndex, T_ELE Element);                    //向指定位置新增一个元素                
    DWORD    capacity();                    //返回在不增容的情况下，还能存储多少元素                
    VOID    clear();                    //清空所有元素                
    BOOL    empty();                    //判断Vector是否为空 返回true时为空                
    VOID    erase(DWORD dwIndex);                    //删除指定元素                
    DWORD    size();                    //返回Vector元素数量的大小                
private:
    BOOL    expand();
private:
    DWORD  m_dwIndex;                        //下一个可用索引                
    DWORD  m_dwIncrement;                        //每次增容的大小                
    DWORD  m_dwLen;                        //当前容器的长度                
    DWORD  m_dwInitSize;                        //默认初始化大小                
    T_ELE* m_pVector;                        //容器指针                
};

//无参构造
template <class T_ELE>
Vector<T_ELE>::Vector()
    :m_dwInitSize(10), m_dwIncrement(5)
{
    //1.创建长度为m_dwInitSize个T_ELE对象
    m_pVector = new T_ELE[m_dwInitSize];
    if (m_pVector == NULL)
    {
        return;
    }
    //2.将新创建的空间初始化                                        
    memset(m_pVector, 0, sizeof(T_ELE) * m_dwInitSize);
    //3.设置其他值
    m_dwIndex = 0;
    m_dwLen = m_dwInitSize;
}

//有参构造                                     
template <class T_ELE>
Vector<T_ELE>::Vector(DWORD dwSize)
    :m_dwIncrement(5)
{
    //1.创建长度为dwSize个T_ELE对象    
    m_pVector = new T_ELE[dwSize];
    if (m_pVector == NULL)
    {
        return;
    }
    //2.将新创建的空间初始化                                        
    memset(m_pVector, 0, sizeof(T_ELE) * dwSize);
    //3.设置其他值    
    m_dwIndex = 0;
    m_dwLen = dwSize;
}

//析构函数                                    
template <class T_ELE>
Vector<T_ELE>::~Vector()
{
    printf("析构函数");
    //释放空间 delete[]    
    delete[] m_pVector;
    m_pVector == NULL;
}

//************扩容*************                                                
template <class T_ELE>
BOOL Vector<T_ELE>::expand()
{
    DWORD dwTempLen = 0;
    T_ELE* pTemp = NULL;
    // 1. 计算增加后的长度                                        
    dwTempLen = m_dwLen + m_dwIncrement;
    // 2. 申请空间                                        
    pTemp = new T_ELE[dwTempLen];
    if (pTemp == NULL)
    {
        return MALLOC_ERROR;
    }
    memset(pTemp, 0, sizeof(T_ELE) * dwTempLen);
    // 3. 将数据复制到新的空间
    memcpy(pTemp, m_pVector, sizeof(T_ELE) * m_dwLen);
    // 4. 释放原来空间                                        
    delete[] m_pVector;
    m_pVector = pTemp;
    pTemp = NULL;
    // 5. 为各种属性赋值                                        
    m_dwLen = dwTempLen;
    return TRUE;
}

//末尾添加                                             
template <class T_ELE>
DWORD  Vector<T_ELE>::push_back(T_ELE Element)
{
    //1.判断是否需要增容，如果需要就调用增容的函数
    if (m_dwIndex >= m_dwLen)
    {
        expand();
    }
    //2.将新的元素复制到容器的最后一个位置
    //memcpy(&m_pVector[m_dwIndex], &Element, sizeof(T_ELE));
    //memcpy(m_pVector + m_dwIndex, &Element, sizeof(T_ELE));
    m_pVector[m_dwIndex] = Element;


    //3.修改属性值                                        
    m_dwIndex++;
    return VSUCCESS;
}

//中间插入                                               
template <class T_ELE>
DWORD  Vector<T_ELE>::insert(DWORD dwIndex, T_ELE Element)
{
    //1.判断索引是否在合理区间 
    if (dwIndex < 0 || dwIndex > m_dwLen)
    {
        return INDEX_ERROR;
    }
    //2.判断是否需要增容，如果需要就调用增容的函数                                        
    if (m_dwIndex >= m_dwLen)
    {
        expand();
    }

    //3.将dwIndex之后的元素后移                                        
    for (int i = m_dwIndex; i > dwIndex; i--)
    {
        memcpy(&m_pVector[i], &m_pVector[i - 1], sizeof(T_ELE));
    }
    /*
    for (int i = m_dwIndex; i > dwIndex; i--) 
    {
        memcpy(m_pVector + i, m_pVector + i - 1, sizeof(T_ELE));
    }
    */

    //4.将Element元素复制到dwIndex位置                                        
    memcpy(m_pVector + dwIndex, &Element, sizeof(T_ELE));
    //5.修改属性值

    return VSUCCESS;
}

//下标获取                                            
template <class T_ELE>
DWORD Vector<T_ELE>::at(DWORD dwIndex, T_ELE* pEle)
{
    //判断索引是否在合理区间                                        
    if (dwIndex < 0 || dwIndex >= m_dwLen)
    {
        return INDEX_ERROR;
    }
    //将dwIndex的值复制到pEle指定的内存                                        
    memcpy(pEle, m_pVector + dwIndex, sizeof(T_ELE));
    return VSUCCESS;
}

//末尾删除
template <class T_ELE>
VOID Vector<T_ELE>::pop_back() {
    //判断是否还有
    if (m_dwLen <= 0)
    {
        printf("一个值也没有了\n");
    }
    //删除
    m_dwIndex--;
    memset(m_pVector + m_dwIndex, 0, sizeof(T_ELE));
}

//********不增容剩余容量********
template <class T_ELE>
DWORD Vector<T_ELE>::capacity() {
    return m_dwLen - m_dwIndex;
}

//*********清空容器*******
template <class T_ELE>
VOID Vector<T_ELE>::clear() {
    memset(m_pVector, 0, sizeof(T_ELE) * (m_dwIndex + 1));
    //修改属性值
    m_dwIndex = 0;
}

//**********判断容器是否为空******
template <class T_ELE>
BOOL Vector<T_ELE>::empty() {
    if (m_pVector) {
        return TRUE;
    }
    else {
        return FALSE;
    }
}

//删除指定元素
template <class T_ELE>
VOID Vector<T_ELE>::erase(DWORD dwIndex) {
    //判断下标是否在有效区间
    if (dwIndex<0 || dwIndex >m_dwIndex) {
        printf("下标越界了\n");
        return;
    }
    //删除
    for (int i = dwIndex; i < m_dwIndex; i++) {
        memcpy(m_pVector + i, m_pVector + i + 1, sizeof(T_ELE));
    }
    m_dwIndex--;
    memset(m_pVector + m_dwIndex, 0, sizeof(T_ELE));

}

//返回元素数量
template <class T_ELE>
DWORD Vector<T_ELE>::size() {
    return m_dwIndex;
}

template <class T_ELE>
void printVector(Vector<T_ELE>* list) {
    for (int i = 0; i < list->size(); i++) {
        T_ELE k;
        list->at(i, &k);
        printf("%d\t", k);
    }
    printf("\n");
}


#include "stdio.h"
#include "Vector_demo.h"

void test()
{
    Vector<int>* list = new Vector<int>(5);
    list->push_back(1);
    list->push_back(2);
    list->push_back(3);
    int a = 0;
    list->at(1, &a);
    printf("%d\n", a);
}

int main() 
{
    test();
    return 0;
}

```

## 读懂每一行反汇编的意思

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