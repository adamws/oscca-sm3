#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <argp.h>
#include <stdlib.h>

#include "../sm3/sm3.h"

int self_test(void);
void print_hash(uint8_t* result);

const char *argp_program_version = "oscca-sm3-example 1.0";
const char *argp_programm_bug_address = "adamws@github";

static char doc[] = "OSCCA SM3 command line hashing tool.";

struct arguments
{
  char *message;
  char *file_path;
  int option;
  int count;
};

static struct argp_option options[] =
{
  {"message", 'm', "MESSAGE", 0, "input message"},
  {"file", 'f', "FILE_PATH", 0, "input file"},
  {0, 't', 0, 0, "self test"},
  {0}
};

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
  struct arguments *arguments = state->input;

  switch(key)
  {
    case 'm':
    {
      arguments->message = arg;
      arguments->option = key;
      arguments->count++;
      break;
    }
    case 'f':
    {
      arguments->file_path = arg;
      arguments->option = key;
      arguments->count++;
      break;
    }
    case 't':
    {
      arguments->option = key;
      arguments->count++;
      break;
    }
    case ARGP_KEY_ARG:
    {
      if(state->arg_num >= 0)
      {
        argp_usage(state);
      }
      break;
    }
    case ARGP_KEY_END:
      if(arguments->count != 1)
      {
        argp_failure(state, 1, 0, "one argument is required");
      }
      break;
    default:
      return ARGP_ERR_UNKNOWN;
  }
  return 0;
}

static struct argp argp =
{
  options,
  parse_opt,
  0,
  doc
};

int main(int argc, char** argv)
{
  struct arguments arguments;
  arguments.message = NULL;
  arguments.file_path = NULL;
  arguments.option = 0;
  arguments.count = 0;

  argp_parse(&argp, argc, argv, 0, 0, &arguments);

  sm3_t ctx;
  uint8_t result[SM3_DIGEST_SIZE];

  switch(arguments.option)
  {
    case 'm':
    {
      if(NULL != arguments.message)
      {
        uint32_t size = strlen(arguments.message);

        sm3_init(&ctx);
        sm3_update(&ctx, (uint8_t*) arguments.message, size);
        sm3_finalize(&ctx, result);
      }
      print_hash(result);
      break;
    }
    case 'f':
    {
      if(NULL != arguments.file_path)
      {
        char *filename = arguments.file_path;
        FILE *input_file = fopen(filename, "rb");
        int bytes = 0;
        unsigned char data[1024];

        if(NULL == input_file)
        {
          printf("Cant open file %s!\n", filename);
          break;
        }

        sm3_init(&ctx);
        while(0 != (bytes = fread(data, 1, 1024, input_file)))
        {
          sm3_update(&ctx, (uint8_t*) data, (uint32_t) bytes);
        }
        sm3_finalize(&ctx, result);
      }
      print_hash(result);
      break;
    }
    case 't':
    {
      self_test();
      break;
    }
    default:
    {
      break;
    }
  }

  exit(0);
}

void print_hash(uint8_t* result)
{
  uint8_t* temp = result;
  for(uint8_t i = 0; i < SM3_DIGEST_SIZE; ++i)
  {
    printf("%02x", *temp++);
  }
  printf("\n");
}

int hashes_equal(char* expected, char* received)
{
  int digest_size = SM3_DIGEST_SIZE;
  while(digest_size--)
  {
    if(*expected++ != *received++)
    {
      return 0;
    }
  }
  return 1;
}

int self_test(void)
{
  char msg_1[0] = "";
  char msg_2[1] = "a";
  char msg_3[3] = "abc";
  char msg_4[26] = "abcdefghijklmnopqrstuvwxyz";
  char msg_5[64] = "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd";
  char msg_6[256]= "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"
                   "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"
                   "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"
                   "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd";

  char exp_1[SM3_DIGEST_SIZE] =
                             {
                              0x1A, 0xB2, 0x1D, 0x83, 0x55, 0xCF, 0xA1, 0x7F,
                              0x8e, 0x61, 0x19, 0x48, 0x31, 0xE8, 0x1A, 0x8F,
                              0x22, 0xBE, 0xC8, 0xC7, 0x28, 0xFE, 0xFB, 0x74,
                              0x7E, 0xD0, 0x35, 0xEB, 0x50, 0x82, 0xAA, 0x2B
                             };

  char exp_2[SM3_DIGEST_SIZE] =
                             {
                              0x62, 0x34, 0x76, 0xAC, 0x18, 0xF6, 0x5A, 0x29,
                              0x09, 0xE4, 0x3C, 0x7F, 0xEC, 0x61, 0xB4, 0x9C,
                              0x7E, 0x76, 0x4A, 0x91, 0xA1, 0x8C, 0xCB, 0x82,
                              0xF1, 0x91, 0x7A, 0x29, 0xC8, 0x6C, 0x5E, 0x88
                             };

  char exp_3[SM3_DIGEST_SIZE] =
                             {
                              0x66, 0xC7, 0xF0, 0xF4, 0x62, 0xEE, 0xED, 0xD9,
                              0xD1, 0xF2, 0xD4, 0x6B, 0xDC, 0x10, 0xE4, 0xE2,
                              0x41, 0x67, 0xC4, 0x87, 0x5C, 0xF2, 0xF7, 0xA2,
                              0x29, 0x7D, 0xA0, 0x2B, 0x8F, 0x4B, 0xA8, 0xE0
                             };

  char exp_4[SM3_DIGEST_SIZE] =
                             {
                              0xB8, 0x0F, 0xE9, 0x7A, 0x4D, 0xA2, 0x4A, 0xFC,
                              0x27, 0x75, 0x64, 0xF6, 0x6A, 0x35, 0x9E, 0xF4,
                              0x40, 0x46, 0x2A, 0xD2, 0x8D, 0xCC, 0x6D, 0x63,
                              0xAD, 0xB2, 0x4D, 0x5C, 0x20, 0xA6, 0x15, 0x95
                             };

  char exp_5[SM3_DIGEST_SIZE] =
                             {
                              0xDE, 0xBE, 0x9F, 0xF9, 0x22, 0x75, 0xB8, 0xA1,
                              0x38, 0x60, 0x48, 0x89, 0xC1, 0x8E, 0x5A, 0x4D,
                              0x6F, 0xDB, 0x70, 0xE5, 0x38, 0x7E, 0x57, 0x65,
                              0x29, 0x3D, 0xCB, 0xA3, 0x9C, 0x0C, 0x57, 0x32
                             };

  char exp_6[SM3_DIGEST_SIZE] =
                             {
                              0xB9, 0x65, 0x76, 0x4C, 0x8B, 0xEB, 0xB0, 0x91,
                              0xC7, 0x60, 0x2B, 0x74, 0xAF, 0xD3, 0x4E, 0xEF,
                              0xB5, 0x31, 0xDC, 0xCB, 0x4E, 0x00, 0x76, 0xD9,
                              0xB7, 0xCD, 0x81, 0x31, 0x99, 0xB4, 0x59, 0x71
                             };

  char result[SM3_DIGEST_SIZE];

  char* inputs[] = {msg_1, msg_2, msg_3, msg_4, msg_5, msg_6};
  uint32_t sizes[] = {0, 1, 3, 26, 64, 256};
  char* expects[] = {exp_1, exp_2, exp_3, exp_4, exp_5, exp_6};

  sm3_t ctx;

  for(int i = 0; i < sizeof(inputs)/sizeof(inputs[0]); ++i)
  {
    sm3_init(&ctx);
    sm3_update(&ctx, (uint8_t*) inputs[i], sizes[i]);
    sm3_finalize(&ctx, (uint8_t*) result);

    printf("Test %d %s\n", i,
           hashes_equal(expects[i], result) ? "passed." : "failed!");
  }

  return 0;
}
