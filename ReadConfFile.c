#include "ReadConfFile.h"

struct CFG_LINK * head=NULL ;
struct CFG_LINK * p=NULL ;
struct CFG_LINK * q=NULL ;


void ReadConfFile( char * FileName )
{
	char str[100];
	int i;
	char c ;
	FILE *fd ;

	fd=fopen(FileName,"r");
	c=fgetc(fd);
	i=0;
	q=(struct CFG_LINK *)malloc(sizeof(struct CFG_LINK));
	p=q;
	head=q;	
	while(c!=EOF)
	{
		if(c==' '||c=='\t')
		{
			c=fgetc(fd);
			continue ;
		}
		if(c=='\n')
		{
			str[i]='\0';
			AnalyseString(str);
			i=0;
			c=fgetc(fd);
			continue ;
		}
		str[i++]=c;
		c=fgetc(fd);
	}
	p->next=NULL;
	free(q);
	q=head;	
}

void AnalyseString(char * string)
{
	int i;
	char str[100];
	char * ch;
	strcpy(str,string);
	for(i=0;i<(int)strlen(str);i++)
	{
		if(str[i]=='#')
			str[i]='\0';
		if(str[i]=='/' && str[i+1]=='/')
			str[i]='\0';
	}
	if(strlen(str)==0) return ;
	if(str[0]=='[')
	{
		for(i=1;i<(int)strlen(str);i++)
		{
			if(str[i]==']')
			{
				q->item[i-1]='\0';
				break ;
			}
			q->item[i-1]=str[i];
		}
		return ;
	}
	else
	{
		if(strlen(q->item)==0)
			strcpy(q->item,p->item);
	}
	if(p!=q)
		p=p->next;
	ch=strchr(str,'=');
	strcpy(p->value,ch+1);
	for(i=0;i<(int)strlen(str);i++)
	{
		if(str[i]=='=')
		{
			p->field[i]='\0';
			break ;
		}
		p->field[i]=str[i];
	}
	q=(struct CFG_LINK *)malloc(sizeof(struct CFG_LINK));
	p->next=q;
}

void ShowCfg()
{
	if ( head != NULL )
	{
		printf( "---------------------------\n" ) ;
		for( p=head ; p!=NULL ; p=p->next )
		{
			printf("---- %s : %s = %s \n",p->item,p->field,p->value);
		}
		printf( "---------------------------\n" ) ;
	}
	
}

char * QueryValue(char * item , char * field)
{
	for( p=head ; p!=NULL ; p=p->next )
	{
		if( strcmp(p->item , item) == 0 )
		{
			if( strcmp(p->field , field) == 0 )
				return p->value ;
		}
	}
	return NULL ;
}

int IsEmpty() 
{
	if( head != NULL )
	{
		return 0 ;
	}
	return 1 ;
}


