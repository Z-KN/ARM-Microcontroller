#include <stdio.h>
#include <string.h>
#include <stdlib.h>

char abstract_name[100]="323b453885f5181f";
int flag;

void verify(char name[]){
    char *inputchar;
    int flen;
    FILE*fp;
    fp=fopen(name,"r");          // 打开文件  
    fseek(fp,0L,SEEK_END);                  // 定位到文件末尾 
    flen=ftell(fp);                         // 得到文件大小  
    inputchar=(char *)calloc(flen+1,1); // 根据文件大小动态分配内存空间  
    // if(inputchar==NULL) 
    // { 
    // fclose(fp); 
    // exit (0);  
    // } 
    fseek(fp,0L,SEEK_SET); // 定位到文件开头  
    fread(inputchar,flen,1,fp); // 一次性读取全部文件内容  
    inputchar[flen]=0; // 字符串结束标志  
    fclose(fp);
    flag=strcmp(abstract_name,inputchar);
    flag=!flag;
}

int main(){
    char a[20]="abstract.txt";
    verify(a);
    printf("%d",flag);
}