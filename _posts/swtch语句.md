找call的时候
	switch	加 表达式，表达式是整数
1.当分支条件三条以内时和if...else...本质上没区别
2.case后面的常量可以是无序的，并不影响大表的生成
3.case 值连续、相近，越相近越好

从连续的case中删掉一个，会把default写在大表里面

四种反汇编
	分支较少/分支较多且不连续			if...else...
	分支较多、且连续					大表
	分支较多、且中间缺失；生成一个小表	大表+小表（生成的小表最多就是一个字节256,）
	case值 超过256						搜索二叉树

switch(表达式)
{
	case 1:
		打坐
		break
	case 2:
		加红
		break
	case 3;
		加蓝
		break
	default：
		break
}

```
	#include <stdio.h>

	void function(int x)
	{
		switch(x)
		{
		case 1:
			printf("1");
			break;
		case 2:
			printf("2");
			break;
		default:
			printf("end");
			break;
		}
	}


	int main(void)
	{
		function(1);
		return 0;
	}

	0040D709   lea         edi,[ebp-44h]
	0040D70C   mov         ecx,11h
	0040D711   mov         eax,0CCCCCCCCh
	0040D716   rep stos    dword ptr [edi]
	0040D718   mov         eax,dword ptr [ebp+8]
	0040D71B   mov         dword ptr [ebp-4],eax
	0040D71E   cmp         dword ptr [ebp-4],1
	0040D722   je          function+2Ch (0040d72c)
	0040D724   cmp         dword ptr [ebp-4],2
	0040D728   je          function+3Bh (0040d73b)
	0040D72A   jmp         function+4Ah (0040d74a)
	0040D72C   push        offset string "1" (0042212c)
	0040D731   call        printf (00401070)
	0040D736   add         esp,4
	0040D739   jmp         function+57h (0040d757)
	0040D73B   push        offset string "%d\n" (0042201c)
	0040D740   call        printf (00401070)
	0040D745   add         esp,4
	0040D748   jmp         function+57h (0040d757)
	0040D74A   push        offset string "%d %d %d %d %d" (00422fb0)
	0040D74F   call        printf (00401070)
	0040D754   add         esp,4
	0040D757   pop         edi
```

```
//当条件较多时,在内存中创建一张大表，把每个分支的代码都存到内存中，通过表达式算出地址

	#include <stdio.h>

	void function(int x)
	{
		switch(x)
		{
		case 1:
			printf("1");
			break;
		case 2:
			printf("2");
			break;
		case 3:
			printf("3");
			break;
		case 4:
			printf("4");
			break;
		case 5:
			printf("5");
			break;
		default:
			printf("end");
			break;
		}
	}


	int main(void)
	{
		function(1);
		return 0;
	}

	00401020   push        ebp
	00401021   mov         ebp,esp
	00401023   sub         esp,44h
	00401026   push        ebx
	00401027   push        esi
	00401028   push        edi
	00401029   lea         edi,[ebp-44h]
	0040102C   mov         ecx,11h
	00401031   mov         eax,0CCCCCCCCh
	00401036   rep stos    dword ptr [edi]
	00401038   mov         eax,dword ptr [ebp+8]
	0040103B   mov         dword ptr [ebp-4],eax
	0040103E   mov         ecx,dword ptr [ebp-4]
	00401041   sub         ecx,1   //此处减的是case的常量中 最小的值
	00401044   mov         dword ptr [ebp-4],ecx
	00401047   cmp         dword ptr [ebp-4],4
	0040104B   ja          $L540+0Fh (004010a2)
	0040104D   mov         edx,dword ptr [ebp-4]
	00401050   jmp         dword ptr [edx*4+4010C0h]
	$L532:
	00401057   push        offset string "1" (00422030)
	0040105C   call        printf (00401160)
	00401061   add         esp,4
	00401064   jmp         $L540+1Ch (004010af)
	$L534:
	00401066   push        offset string "2" (0042202c)
	0040106B   call        printf (00401160)
	00401070   add         esp,4
	00401073   jmp         $L540+1Ch (004010af)
	$L536:
	00401075   push        offset string "3" (00422028)
	0040107A   call        printf (00401160)
	0040107F   add         esp,4
	00401082   jmp         $L540+1Ch (004010af)
	$L538:
	00401084   push        offset string "4" (00422024)
	00401089   call        printf (00401160)
	0040108E   add         esp,4
	00401091   jmp         $L540+1Ch (004010af)
	$L540:
	00401093   push        offset string "5" (00422020)
	00401098   call        printf (00401160)
	0040109D   add         esp,4
	004010A0   jmp         $L540+1Ch (004010af)
	004010A2   push        offset string "end" (0042201c)
	004010A7   call        printf (00401160)
	004010AC   add         esp,4
	004010AF   pop         edi
	004010B0   pop         esi
	004010B1   pop         ebx
```

作业：
	1.写一个switch语句，不生成大表、不生成小表，贴出对应的反汇编
		#include <stdio.h>

		void function(int x)
		{
			switch(x)
			{
			case 1:
				printf("1");
				break;
			case 2:
				printf("2");
				break;
			case 3:
				printf("3");
				break;
			default:
				printf("end");
				break;
			}
		}


		int main(void)
		{
			function(1);
			return 0;
		}
	2.写一个switch，只生成大表，贴出反汇编
		#include <stdio.h>

		void function(int x)
		{
			switch(x)
			{
			case 1:
				printf("1");
				break;
			case 2:
				printf("2");
				break;
			case 3:
				printf("3");
				break;
			case 4:
				printf("4");
				break;
			case 5:
				printf("5");
				break;
			case 6:
				printf("6");
				break;
			case 7:
				printf("7");
				break;
			default:
				printf("end");
				break;
			}
		}


		int main(void)
		{
			function(1);
			return 0;
		}
	3.写一个switch，只生成大、小表，贴出反汇编
	
		#include <stdio.h>

		void function(int x)
		{
			switch(x)
			{
			case 1:
				printf("1");
				break;
			case 2:
				printf("2");
				break;
			case 3:
				printf("3");
				break;
			case 4:
				printf("4");
				break;
			case 5:
				printf("5");
				break;
			case 6:
				printf("6");
				break;
			case 18:
				printf("7");
				break;
			default:
				printf("end");
				break;
			}
		}


		int main(void)
		{
			function(1);
			return 0;
		}
			
		0040D801   mov         eax,0CCCCCCCCh
		0040D806   rep stos    dword ptr [edi]
		0040D808   mov         eax,dword ptr [ebp+8]
		0040D80B   mov         dword ptr [ebp-4],eax
		0040D80E   mov         ecx,dword ptr [ebp-4]
		0040D811   sub         ecx,1
		0040D814   mov         dword ptr [ebp-4],ecx
		0040D817   cmp         dword ptr [ebp-4],11h
		0040D81B   ja          $L544+0Fh (0040d898)
		0040D81D   mov         eax,dword ptr [ebp-4]
		0040D820   xor         edx,edx
		0040D822   mov         dl,byte ptr  (0040d8d6)[eax]
		0040D828   jmp         dword ptr [edx*4+40D8B6h]

	4.为while语句写反汇编
	
		#include <stdio.h>

		void function(int x)
		{
			while(x>10)
			{
				printf("%d\n",x);
				x--;
			}
		}


		int main(void)
		{
			function(15);
			return 0;
		}
			
		0040D808   cmp         dword ptr [ebp+8],0Ah
		0040D80C   jle         function+3Ah (0040d82a)
		0040D80E   mov         eax,dword ptr [ebp+8]
		0040D811   push        eax
		0040D812   push        offset string "end" (0042201c)
		0040D817   call        printf (00401160)
		0040D81C   add         esp,8
		0040D81F   mov         ecx,dword ptr [ebp+8]
		0040D822   sub         ecx,1
		0040D825   mov         dword ptr [ebp+8],ecx
		0040D828   jmp         function+18h (0040d808)
		0040D82A   pop         edi

	5.为for语句写反汇编
	
	#include <stdio.h>

	void function(int x)
	{
		for(int i=0;i<x;i++)
		{
			printf("%d\n",i);
		}
	}


	int main(void)
	{
		function(3);
		return 0;
	}
	
	0040D806   rep stos    dword ptr [edi]
	0040D808   mov         dword ptr [ebp-4],0
	0040D80F   jmp         function+2Ah (0040d81a)
	0040D811   mov         eax,dword ptr [ebp-4]
	0040D814   add         eax,1
	0040D817   mov         dword ptr [ebp-4],eax
	0040D81A   mov         ecx,dword ptr [ebp-4]
	0040D81D   cmp         ecx,dword ptr [ebp+8]
	0040D820   jge         function+45h (0040d835)
	0040D822   mov         edx,dword ptr [ebp-4]
	0040D825   push        edx
	0040D826   push        offset string "end" (0042201c)
	0040D82B   call        printf (00401160)
	0040D830   add         esp,8
	0040D833   jmp         function+21h (0040d811)

	6.写出do...while反汇编
	#include <stdio.h>

	void function(int x)
	{
		do
		{
			printf("%d\n",x);
			x--;
		}while(x>1);
	}


	int main(void)
	{
		function(3);
		return 0;
	}
	
	
	0040D806   rep stos    dword ptr [edi]
	0040D808   mov         eax,dword ptr [ebp+8]
	0040D80B   push        eax
	0040D80C   push        offset string "end" (0042201c)
	0040D811   call        printf (00401160)
	0040D816   add         esp,8
	0040D819   mov         ecx,dword ptr [ebp+8]
	0040D81C   sub         ecx,1
	0040D81F   mov         dword ptr [ebp+8],ecx
	0040D822   cmp         dword ptr [ebp+8],1
	0040D826   jl          function+18h (0040d808)