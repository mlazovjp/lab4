// ConsoleApplication1.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <stdio.h>
#include <string.h>

void func1(char *str1, char *str2) {

	char temp[5];
	strcpy(temp, str1);

	printf("func1 Before: str1=%s, str2=%s\n", str1, str2);
	strcpy(str1, str2);
	printf("func1 After: str1=%s, str2=%s\n", str1, str2);

	strcpy(str1, temp);
	printf("func1 Reset: str1=%s, str2=%s\n", str1, str2);

}

void func2() {

	char str[80];
	printf("func2 about to execute sprintf\n");
	sprintf(str, "Value of Pi = %f\n", 3.14);
	puts(str);

}

void func3() {
	char temp1[] = "JKLM";
	char temp2[] = "NOPQ";
	strcpy(temp1, temp2);

	func2();
}

void func4() {

	printf("\nfunc4 about to execute func2\n");
	func2();

	printf("func4 about to execute func3\n");
	func3();

}
/*
extern void export1(void) {

	printf("export1()\n");
	func3();
	func4();

}
*/

extern "C" void foo() {
	printf("foo");
}


int main()
{

	char strABCD[] = "ABCD";
	char strEFGH[] = "EFGH";

	printf("Start\n");

	func1(strABCD, strEFGH);
	func2();
	func3();

	//export1();
	foo();

    return 0;
}

