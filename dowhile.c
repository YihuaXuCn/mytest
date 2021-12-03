#include <stdio.h>
// #include <conio.h>

void main()
{
 int num, rem, rev=0, copy;
 // clrscr();
 printf("Enter number: ");
 scanf("%d", &num);
 copy = num;
 
 do
 {
  rem = num%10;
  rev = rev*10 + rem;
  num = num/10;
 } while(num!=0);

 if(rev==copy)
 {
  printf("PALINDROME");
 }
 else
 {
  printf("NOT PALINDROME");
 }
 // getch();
}
