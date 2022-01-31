#include <stdio.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>
int PASS2()
{
	int locctr=0X0, start=0X0, sa=0X0, program_length=0X0, ret, op_status = 0, address=0X0, target=0X0, ascii=0X0, temp1=0X0, j, k, count=0X0, record_len=0X0;
	char label[12], mnemonic[8], operand[12], buffer[64], mnem[8], op[2], symbol[12], opcode[2], cons[8];
	long int aseek,bseek;
	FILE *FINTER, *FSYMTAB, *FOPTAB, *FLENGTH, *F;
	
	FINTER = fopen("Inter.txt","r");
	if(FINTER == NULL)
         {
            printf("\nIntermediate file missing!"); 
            return 0;
          }
       FSYMTAB=fopen("SYMTAB.txt","r");
       if(FSYMTAB == NULL)
       {
         printf("\nSYMTAB missing!");
         return 0;
       }
      FOPTAB=fopen("OPTAB.txt","r");
      if(FOPTAB == NULL)
      {
        printf("\nOPTAB missing!");
        return 0;
       }
    FLENGTH=fopen("Program Length.txt","r");
    if(FLENGTH == NULL)
    {
     printf("\nProgram_length file missing!"); 
     return 0;
     }
    F = fopen("Object_Program.txt","w");
    
    fscanf(FINTER,"%X%s%s%s",&locctr,label,mnemonic,operand);
    if(strcmp(mnemonic,"START")==0)
     {
        start = (int)strtol(operand,NULL,16);
        fscanf(FLENGTH,"%X",&program_length);
        fprintf(F,"H^%6s^%06X^%06X",label,start,program_length);
    	fprintf(F,"\nT^%06X^00^",start);
    	bseek = ftell(F);
        printf("hi");

      }
	    
    fgets(buffer,64,FINTER);
	while(!feof(FINTER))
	{
		fgets(buffer,64,FINTER);
		ret = sscanf(buffer,"%X%s%s%s",&locctr,label,mnemonic,operand);

		if(ret == 2) //in case of RSUB
		{
			strcpy(mnemonic,label);
		}
		else if(ret == 3)	//label not present
		{
			strcpy(operand,mnemonic);
			strcpy(mnemonic,label);
		}
		//else
		//{}

		if(count >= 0X3C || strcmp(mnemonic,"RESB")==0 || strcmp(mnemonic,"RESW")==0 || strcmp(mnemonic,"END")==0)	//0X3C is hex equivalent of 60
		{
			aseek = ftell(F);
			fseek(F,-(aseek-bseek)-3L,1);
			record_len = count/0X2;
			fprintf(F,"%02X^",record_len);
			fseek(F,0L,2);
			if(strcmp(mnemonic,"END")==0)
			{
				break;
			}
			sa = locctr;
			if(strcmp(mnemonic,"RESW")!=0)
			{
				fprintf(F,"\nT^%06X^00^",sa);
			}
			bseek = ftell(F);
			count = 0X0;
		}
		
		rewind(FOPTAB);
                op_status = 0;
		while(!feof(FOPTAB))
		{
			//printf("Insideoptabwhileloop.\t");	
			fscanf(FOPTAB,"%s%s",mnem,op);
			if(strcmp(mnemonic,mnem)==0)
			{
				strcpy(opcode,op);
				op_status = 1;
				break;
			}
		}
		//printf("op_status=%d\tmnemonic=%s",op_status,mnemonic);
		if(op_status == 1 && operand[j-1]=='X' && operand[j-2]==',')
		{
			//printf("CondnforBUFFER,X.");
			j = strlen(operand);
			operand[j-2] = '\0';
			rewind(FSYMTAB);
			fscanf(FSYMTAB,"%s%X",symbol,&address);
			while(!feof(FSYMTAB))
			{
				//printf("InsideSymtab.\t");
				if(strcmp(operand,symbol)==0)
				{
					target = address;
					target += 0X8000;
					break;
				}
			}
			fprintf(F,"%2s%04X^",opcode,target);
			count = count+0X6;
			continue;
		}
               else if (op_status == 1 && strcmp(mnemonic,"RSUB")!=0)
		{
			//printf("MnemonicisnotRSUB.");
			rewind(FSYMTAB);
			while(!feof(FSYMTAB))
			{
				//printf("Inside Symtab\t");
				fscanf(FSYMTAB,"%s%X",symbol,&address);
				if(strcmp(operand,symbol)==0)
				{
					target = address;
					break;
				}
			}
			printf("\nopcode=%s\ttarget=%X\n",opcode,target);
			fprintf(F,"%2s%04X^",op,target);
			count = count+0X6;
			continue;
		}
		else if (op_status == 1 && strcmp(mnemonic,"RSUB")==0)
		{
			//printf("MnemonicisRSUB.");
			fprintf(F,"%s0000^",opcode);
			count = count+0X6;
			continue;
		}
		else	//In case mnemonic field is an assembly directive.
		{
			//printf("Assemblydirective.");
			if((strcmp(mnemonic,"BYTE")==0) || ((strcmp(mnemonic,"BYTE")==0)))
			{
				if(operand[0] == 'C')
				{
					for(k=0;k<strlen(operand)-3;k++)
					{
						temp1=0x0;
						temp1=temp1+(int)operand[k+2];
						ascii=ascii* 0x100 + temp1;
					}			
					fprintf(F,"%6X^",ascii);
					count = count+strlen(operand)-0X3;
				}
				else	//strcmp(operand[0] == 'X'
				{
					for(k=0;k<strlen(operand)-3;k++)
					{
						cons[k]=operand[k+2];
}   
					cons[k]='\0';
					fprintf(F,"%s^",cons);
					count = count + (strlen(cons)+0X0);
				}
				continue;
			}
			else if((strcmp(mnemonic,"WORD")==0) || (strcmp(mnemonic,"word")==0))
			{
				temp1 = (int)strtol(operand,NULL,10);
				fprintf(F,"%06X^",temp1);
				count = count+0X6;
				continue;
			}
			else	// in case of RESB or RESW
			{
				continue;
			}
		}
	}
	fprintf(F,"\nE^%06X",start);
	printf("\nObject Program written successfully!\n");
	fclose(FINTER);
	fclose(FSYMTAB);
	fclose(FOPTAB);
	fclose(FLENGTH);
	fclose(F);
	return 1;
}
void main()
{
 PASS2();
}

