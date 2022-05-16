
/**************************************************
* File name: test_demo.c
* Author: HAN Wei
* Author's blog: https://blog.csdn.net/henter/
* Date: Nov 20th, 2018
* Description: implement test demo program for
	SM2 signature creation and verification
	GitHub��https://github.com/greendow/SM2-signature-creation-and-verification
**************************************************/

#include <stdio.h>
#include <stdlib.h>
#include "test_sm2_sign_and_verify.h"
#include "ecdsa.h"

int Ecdsa::SM2main(void)
{
	int error_code;


	/*
	if ( error_code = test_with_input_defined_in_standard() )
	{
	   printf("Test SM2 sign data and verify signature with input defined in standard failed!\n");
	   return error_code;
	}
	else
	{
	   printf("Test SM2 sign data and verify signature with input defined in standard succeeded!\n");
	}

	printf("\n/*********************************************************//*\n");*/

	SM2keypair();//����SM2��Կ˽Կ�Եĺ���

	if (error_code = sm2_sign())//SM2ǩ������ 
	{
		printf("\t\tǩ��ʧ�ܣ�\n");
		return error_code;
	}

	else if (error_code = sm2_verify())//SM2��ǩ����
	{
		printf("\t\t��ǩʧ�ܣ�\n");
		return error_code;
	}
	else
	{
		printf("\t\tSM2��Կ�����ɳɹ���ǩ����ǩ�ɹ�!\n");
	}

#if defined(_WIN32) || defined(_WIN64)
	system("pause");
#endif
	return 0;
}
