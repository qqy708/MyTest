
/**************************************************
* File name: test_demo.c
* Author: HAN Wei
* Author's blog: https://blog.csdn.net/henter/
* Date: Nov 20th, 2018
* Description: implement test demo program for
	SM2 signature creation and verification
	GitHub：https://github.com/greendow/SM2-signature-creation-and-verification
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

	SM2keypair();//生成SM2公钥私钥对的函数

	if (error_code = sm2_sign())//SM2签名函数 
	{
		printf("\t\t签名失败！\n");
		return error_code;
	}

	else if (error_code = sm2_verify())//SM2验签函数
	{
		printf("\t\t验签失败！\n");
		return error_code;
	}
	else
	{
		printf("\t\tSM2密钥对生成成功，签名验签成功!\n");
	}

#if defined(_WIN32) || defined(_WIN64)
	system("pause");
#endif
	return 0;
}
