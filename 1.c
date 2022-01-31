#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<math.h>
int PASS1()
{
 char buffer[64],label[10],mnemonic[10],operand[10],mnem[10],op[2],symbol[10];
 int start=0X0,locctr=0X0,ret,flag=0,address=0X0,j,pgl=0X0,count=0X0;
 FILE *F,*FSYMTAB,*FOPTAB,*FINTER,*FLENGTH;
 F=fopen("SIC_program.txt","r");
 if(F==NULL)
 {
  printf("SOURCEFILE MISSING");
  return 0;
 }
FSYMTAB=fopen("SYMTAB.txt","w+");
FOPTAB=fopen("OPTAB.txt","r");
if(FOPTAB==NULL)
 {
   printf("OPTAB MISSING");
   return 0;
 }
FINTER=fopen("Inter.txt","w");
fgets(buffer,64,F);
sscanf(buffer,"%s%s%s",label,mnemonic,operand);
if(strcmp(mnemonic,"START")==0)
{ 
  locctr=atoi(operand);
  while(locctr>0)
  {
    start=start+(locctr%10)*pow(16,count);
    locctr=locctr/10;
    count++;
  }
  locctr=start;
  fprintf(FINTER,"%X\t%s\t%s\t%s\n",start,label,mnemonic,operand);
}
else
{
  locctr=0X0;
}
while(!feof(F))
	{
		fgets(buffer,64,F);
		ret = sscanf(buffer,"%s%s%s",label,mnemonic,operand);

		if(label[0] != ';' && label[0] != '.')	//not a comment line
		{	
			if(ret == 1)
			{
				strcpy(mnemonic,label);
				fprintf(FINTER,"%04X\t\t%s\n",locctr,mnemonic);
			}
			if(ret == 2)
			{
				strcpy(operand,mnemonic);
				strcpy(mnemonic,label);
				fprintf(FINTER,"%X\t\t%s\t%s\n",locctr,mnemonic,operand);
			}
			if(ret == 3) //there is a symbol in the Label field
			{
				rewind(FSYMTAB);		
				while(!feof(FSYMTAB))
				{
					flag = 0;
					fscanf(FSYMTAB,"%s%X",symbol,&address);
					if(strcmp(label,symbol)==0)
					{
						flag = 1;	//duplicate symbol found
						printf("\nDuplicate LABEL found: %s",label);
						return 0;
					}
				}					
				
				if(flag == 0)	//no duplicate symbol
				{
					fprintf(FSYMTAB,"%s\t%X\n",label,locctr);
					fprintf(FINTER,"%X\t%s\t%s\t%s\n",locctr,label,mnemonic,operand);
				}
			}
			
			rewind(FOPTAB);
			while(!feof(FOPTAB))	//search optab for OPCODE
			{
fscanf(FOPTAB,"%s%s",mnem,op);
				if(strcmp(mnemonic,mnem)==0)
				{
					locctr += 3;
					flag = 0;
					break;
				}
				else if(strcmp(mnemonic,"WORD")==0 || strcmp(mnemonic,"word")==0)
				{	
					locctr += 3;
					flag = 0;
					break;
				}
				else if((strcmp(mnemonic,"RESW")==0) || (strcmp(mnemonic,"resw")==0))
				{	
					locctr += 3*atoi(operand);
					flag = 0;
					break;
				}
				else if(strcmp(mnemonic,"RESB")==0 || strcmp(mnemonic,"resb")==0)
				{	
					locctr += atoi(operand);
					flag = 0;
					break;
				}
				else if(strcmp(mnemonic,"BYTE")==0 || strcmp(mnemonic,"byte")==0)
				{
					j = strlen(operand);
if(operand[0] !='C' && operand[0] != 'X')
					{	
						locctr += 1;
						flag = 0;
						break;
					}
					else if(strcmp(mnemonic,"BYTE")==0 && operand[0] =='C')
					{
						locctr += j-3;	//-3 is done to account for C' '
						flag = 0;
						break;
					}
					else if(strcmp(mnemonic,"BYTE")==0 && operand[0] =='X')
					{	
						if((j-3)%2 != 0)
							locctr += (j-3)/2 + 1;
						else
							locctr += (j-3)/2 ;
						flag = 0;
						break;
					}
					else
					{
						flag = 1;
					}
				}
				if(flag == 1)
				{
					printf("\n%s not present in OPTAB!",mnemonic);
					printf("\nExiting ...");
					return 0;
				}
			}
		}
		if(strcmp(mnemonic,"END")==0)
{
			break;
		}
	}
	printf("\nSYMTAB generated...\n");
	
	FLENGTH = fopen("Program Length.txt","w");
	pgl = locctr - start;
	fprintf(FLENGTH,"%X",pgl);
	
	fclose(F);
	fclose(FSYMTAB);
	fclose(FOPTAB);
	fclose(FINTER);
	fclose(FLENGTH);
	return 1;
}
void main()
{ 
 int k=PASS1();
}
