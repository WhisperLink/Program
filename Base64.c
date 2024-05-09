#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#pragma warning(disable:4996)
#pragma warning(disable:6031)


const char* base64_table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";



void menu() {
	printf("    >>> 1. Base64 encoding\n");
	printf("    >>> 2. Base64 decoding\n\n");
}


char* encoding(const char* plainText, size_t data_length) {
	size_t decoding_length = 4 * ((data_length + 2) / 3);
	char* encoded_data = (char*)malloc(decoding_length + 1);

	if (encoded_data == NULL) {
		return NULL;
	}

	for (unsigned int i = 0, j = 0; i < data_length;) {
		unsigned int data_1 = i < data_length ? *(plainText + (i++)) : 0;
		unsigned int data_2 = i < data_length ? *(plainText + (i++)) : 0;
		unsigned int data_3 = i < data_length ? *(plainText + (i++)) : 0;

		unsigned int data_1_two_bit = data_1 & 0x3;
		unsigned int data_2_four_bit = data_2 & 0xF;

		// 48 65 6c 6c 6f 20 68 34 63 21 21
		*(encoded_data + (j++)) = *(base64_table + ((data_1 & 0xFC) >> 2));
		// printf("%c", encoded_data[j-1]);
		*(encoded_data + (j++)) = *(base64_table + ((data_1_two_bit << 4 | (data_2 >> 4)) & 0x3F));
		// printf("%c", encoded_data[j-1]);
		*(encoded_data + (j++)) = *(base64_table + ((data_2_four_bit << 2 | (data_3 >> 6)) & 0x3F));
		// printf("%c", encoded_data[j-1]);
		*(encoded_data + (j++)) = *(base64_table + (data_3 & 0x3F));
		// printf("%c", encoded_data[j-1]);
	}

	for (size_t i = 0; i < (size_t)(3 - data_length % 3) % 3; i++) {
		*(encoded_data + (decoding_length - 1 - i)) = '=';
	}

	*(encoded_data + decoding_length) = '\0';

	return encoded_data;
}


char* decoding(const char* cipherText, size_t encoded_length) {
	size_t decoding_length = 0;
	int* decode_base64_table;
	int num = 52;
	decode_base64_table = (int*)malloc(sizeof(int) * 256);

	for (int i = 0; i < 256; i++)
		*(decode_base64_table + i) = -1;

	*(decode_base64_table + 43) = 62;
	*(decode_base64_table + 47) = 63;

	for (int i = 48; i < 58; i++) {
		*(decode_base64_table + i) = num;
		num++;
	}
	for (int i = 65, j = 0; i < 91; i++, j++) {
		*(decode_base64_table + i) = j;
	}
	for (int i = 97, j = 26; i < 123; i++, j++)
		*(decode_base64_table + i) = j;

	
	if (encoded_length % 4 != 0) {
		return NULL;
	}

	decoding_length = encoded_length / 4 * 3;
	char* decoded_data = (char*)malloc(decoding_length + 1);

	if (decoded_data == NULL) {
		return NULL;
	}

	if (*(cipherText + encoded_length - 1) == '=') {
		decoding_length--;
	}
	if (*(cipherText + encoded_length - 2) == '=') {
		decoding_length--;
	}

	for (size_t i = 0, j = 0; i < encoded_length;) {
		unsigned int data_a = *(cipherText + i) == '=' ? 0 & i++ : *(decode_base64_table + (*(cipherText + (i++))));
		unsigned int data_b = *(cipherText + i) == '=' ? 0 & i++ : *(decode_base64_table + (*(cipherText + (i++))));
		unsigned int data_c = *(cipherText + i) == '=' ? 0 & i++ : *(decode_base64_table + (*(cipherText + (i++))));
		unsigned int data_d = *(cipherText + i) == '=' ? 0 & i++ : *(decode_base64_table + (*(cipherText + (i++))));

		// 53 47 56 73 62 47 38 67 61 44 52 6a 49 53 45 3d
		unsigned int dword = (data_a << 3 * 6) + (data_b << 2 * 6) + (data_c << 1 * 6) + (data_d << 0 * 6);


		if (j < decoding_length) {
			*(decoded_data + (j++)) = (dword >> 2 * 8) & 0xFF;
		}
		if (j < decoding_length) {
			*(decoded_data + (j++)) = (dword >> 1 * 8) & 0xFF;
		}
		if (j < decoding_length) {
			*(decoded_data + (j++)) = (dword >> 0 * 8) & 0xFF;
		}
	}
	free(decode_base64_table);
	return decoded_data;
}


int main()
{
	for (; ;)
	{
		int num = 0, len = 0;
		char* filename = (char*)malloc(50 * sizeof(char));
		if (filename == NULL) {
			printf("메모리 할당 실패\n:");
			return 1;
		}
		void* filedata;
		char* encodetext;
		char* decodetext;
		FILE* fp = NULL;
		__int64_t size = 0;
		menu();
		printf("Input# ");
		scanf("%d", &num);

		switch (num)
		{
		case 1:
			printf("Input# ");
			getchar();
			fgets(filename, 50, stdin);
			fp = fopen(filename, "r+");
			if (fp == NULL) {
				printf("파일 열기 실패\n");
				return 1;
			};
			fseek(fp, 0, SEEK_END);
			size = ftell(fp);
			fseek(fp, 0, SEEK_SET);
			filedata = (char*)malloc(sizeof(char)*(size+1));
			//while ((fgets(filedata, size + 1, fp) != NULL))
			memset(filedata, 0, size + 1);
			fread(filedata, size, 1, fp);
			fclose(fp);
			encodetext = (char*)malloc(sizeof(char)*(4 * ((strlen(filedata) + 2) / 3)));
			encodetext = encoding(filedata, strlen(filedata)); // encodetext에 메모리를 따로 할당해주지않아서 세그멘테이션 오류 발생(의문: 하지만 할당안해줬을 때 몇 번 실행되는 이유는 뭐였을까?)
			fp = fopen(filename, "wt");
			if (fp == NULL) {
				printf("파일 열기 실패\n");
				return 1;
			}
			fprintf(fp, "%s", encodetext);
			free(encodetext);
			free(filedata);
			fclose(fp);
			break;
		case 2:
			printf("Input# ");
			getchar();
			fgets(filename, 50, stdin);
			fp = fopen(filename, "rt");
			if (fp == NULL) {
				printf("파일 열기 실패\n");
				return 0;
			}
			fseek(fp, 0, SEEK_END);
			size = ftell(fp);
			fseek(fp, 0, SEEK_SET);
			// while ((fgets(filedata, size + 1, fp) != NULL)
			filedata = (char*)malloc(sizeof(char)*(size+1));
			fread(filedata, size+1, 1, fp);
			fclose(fp);
			decodetext = (char*)malloc(sizeof(char) * (strlen(filedata) / 4 * 3));
			decodetext = decoding(filedata, strlen(filedata));
			fp = fopen(filename, "wt");
			if (fp == NULL) {
				printf("파일 열기 실패\n");
				return 0;
			}
			fprintf(fp, "%s", decodetext);
			free(decodetext);
			free(filedata);
			fclose(fp);
			break;
		default:
			printf("잘못 입력하셨습니다.\n");
			return 0;
		}
	}
}
