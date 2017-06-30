#include <stdio.h>
#include <stdlib.h>
//using namespace std;
typedef unsigned char BYTE;
typedef struct BLOCKHEADER{
  BYTE version[4];
  BYTE previousHash[32];
  BYTE merkleHash[32];
  BYTE timestamp[4];
  BYTE bits[4];
  BYTE nonce[4];
}BLOCKHEADER;
typedef struct TXINPUT{
  BYTE previous_output_hash[32];
  BYTE previous_output_index[4];
  BYTE *script_length;
  BYTE *signature_script;
  BYTE sequence[4];
}TXINPUT;

typedef struct TXOUTPUT{
  BYTE value[8];
  BYTE *pk_script_length;
  BYTE *pk_script;
}TXOUTPUT;

typedef struct TX{
  BYTE version[4];
  BYTE *numinputs;
  TXINPUT *inputs;
  BYTE *numoutputs;
  TXOUTPUT *outputs;
  BYTE locktime;
}TX;

typedef struct TXINFO{
  BYTE *txcount;
  TX   *txs;
}TXINFO;

typedef struct BLOCK{
  BLOCKHEADER *blockheader;
  TXINFO *blockbody;
}BLOCK;

typedef struct BLOCKFILE{
  BYTE magic[4];
  BYTE blocksize[4];
  BLOCK *block;
  BYTE space[8];
}BLOCKFILE;

BYTE* varint(FILE *f);
int64_t decodeVarint(BYTE *varint);
BYTE *readLength(int64_t length,FILE *f);
BLOCKFILE *getBlockFile(FILE *f);
BLOCK *getBlock(FILE *f);
BLOCKHEADER *getBlockHeader(FILE *f);
TX *getTx(FILE *f);
TXINPUT *getTxInput(FILE *f);
TXOUTPUT *getTxOutput(FILE *f);
int main(int argc,char **args)
{ 
  FILE *f=fopen(*(args+1),"rb");
  getBlockFile(f);
  
  return 0;
}


BYTE* varint(FILE *f){
  BYTE *ptrByte=malloc(9);
  fread(ptrByte,1,1,f);
  if (*ptrByte >= 0xfd){
    fread(ptrByte+1,2<<(*ptrByte&0xf3),1,f);
  }
  return ptrByte;
}

int64_t decodeVarint(BYTE *varint){
  if(*varint>=0xfd)
  ++varint;
  if(*varint==0xfd)
    return (int64_t)*(int16_t*)(varint);
  if(*varint==0xfe)
    return (int64_t)*(int32_t*)(varint);
  if(*varint==0xff)
    return *(int64_t*)(varint);
  return (int64_t)*(int8_t*)varint;
}
BYTE *readLength(int64_t length,FILE *f){
  BYTE* result=malloc(length);
  fread(result,length,1,f);
  return result;
}

BLOCK *getBlock(FILE *f){
  
  
  // printf("======block header======\n");
  // fread(&block->blockheader,80,1,f);
  // BLOCKHEADER blockheader=block->blockheader;
  // printf("version:%d\n",*((int*)blockheader.version) );

  // printf("previousHash:");
  // for(int i=31 ; i>=0 ; i--){
  //   printf("%02x",blockheader.previousHash[i]);
  // }
  // printf("\nmerkleHash:");
  // for(int i=31 ; i>=0 ; i--){
  //   printf("%02x",blockheader.merkleHash[i]);
  // }
  // printf("\n");
  // printf("timestamp:%d\n",(*(int*)blockheader.timestamp) );
  // printf("bits:%x(%d)\n",(*(int*)blockheader.bits),(*(int*)blockheader.bits) );
  // printf("nonce:%u\n",(*(unsigned int*)blockheader.nonce) );
  
  BLOCK *block=malloc(sizeof(BLOCK));
  block->blockheader=getBlockHeader(f);
  block->blockbody=malloc(sizeof(TXINFO));
  block->blockbody->txcount=varint(f);
  printf("========tx=========\n");
  printf("tx count:%lld\n", decodeVarint(block->blockbody->txcount) ) ;
  
  block->blockbody->txs=malloc(sizeof(TX)*(*(int *)(*(block->blockbody)).txcount) );

  fread( &(block->blockbody->txs[0]),4,1,f);
  printf("tx version:%d\n", *(block->blockbody->txs[0]).version ) ;

  block->blockbody->txs[0].numinputs=varint(f);
  printf("tx input count:%lld\n",decodeVarint(block->blockbody->txs[0].numinputs) );
  printf("========tx input=========\n");
  printf("previous_output_hash:");
  block->blockbody->txs[0].inputs=malloc(sizeof(TXINPUT)*(*(int *)(block->blockbody->txs[0].numinputs)) );
  fread(block->blockbody->txs[0].inputs->previous_output_hash,32,1,f);
  for(int i=31 ; i>=0 ; i--){
    printf("%02x",block->blockbody->txs[0].inputs->previous_output_hash[i]);
  }
  printf("\n");
  fread(block->blockbody->txs[0].inputs->previous_output_index,4,1,f);
  printf("previous_output_index:%ld\n",*(int *)(block->blockbody->txs[0].inputs->previous_output_index));
  block->blockbody->txs[0].inputs->script_length=varint(f);
  printf("script_lenght:%lld\n",decodeVarint(block->blockbody->txs[0].inputs->script_length));
  block->blockbody->txs[0].inputs->signature_script=readLength(decodeVarint(block->blockbody->txs[0].inputs->script_length),f);
  printf("script:");
  for(int i=0;i<*(int *)(block->blockbody->txs[0].inputs->script_length);i++)
  {
    printf("%02x",block->blockbody->txs[0].inputs->signature_script[i]);
  }
  printf("\n");
  fread( block->blockbody->txs[0].inputs->sequence,4,1,f);
  printf("sequence:%ld\n",*(int *)block->blockbody->txs[0].inputs->sequence);
  printf("========tx output========\n");
  block->blockbody->txs[0].numoutputs=varint(f);
  printf("tx output count:%lld\n",decodeVarint(block->blockbody->txs[0].numoutputs) );
  block->blockbody->txs[0].outputs=malloc(sizeof(TXOUTPUT)*(*(int *)(block->blockbody->txs[0].numoutputs)) );
  /////////////////
  fread(block->blockbody->txs[0].outputs->value,8,1,f);
  printf("value:%lld\n",*(long long int *)block->blockbody->txs[0].outputs->value);
  block->blockbody->txs[0].outputs->pk_script_length=varint(f);
  printf("pk_script_length:%lld\n",decodeVarint(block->blockbody->txs[0].outputs->pk_script_length) );
  block->blockbody->txs[0].outputs->pk_script=readLength(decodeVarint(block->blockbody->txs[0].outputs->pk_script_length),f);
  printf("script");
  for(int i=0;i<*(int *)block->blockbody->txs[0].outputs->pk_script_length;i++)
  {
    printf("%02x",block->blockbody->txs[0].outputs->pk_script[i]);
  }
  printf("\n");
  //////////////////
  
  
  return block;
}
BLOCKHEADER *getBlockHeader(FILE *f){
  BLOCKHEADER *blockheader;
  blockheader=malloc(80);
  printf("======block header======\n");
  fread(blockheader,80,1,f);
  printf("version:%d\n",*((int*)blockheader->version) );

  printf("previousHash:");
  for(int i=31 ; i>=0 ; i--){
    printf("%02x",blockheader->previousHash[i]);
  }
  printf("\nmerkleHash:");
  for(int i=31 ; i>=0 ; i--){
    printf("%02x",blockheader->merkleHash[i]);
  }
  printf("\n");
  printf("timestamp:%d\n",(*(int*)blockheader->timestamp) );
  printf("bits:%x(%d)\n",(*(int*)blockheader->bits),(*(int*)blockheader->bits) );
  printf("nonce:%lld\n",(*(int64_t*)blockheader->nonce) );
  return (blockheader);
}

BLOCKFILE *getBlockFile(FILE *f){
  BLOCKFILE *blockfile=malloc(sizeof(BLOCKFILE));
  blockfile->block=malloc(sizeof(BLOCK));
  fread(blockfile,8,1,f);
  printf("magic value:%x\n",*((int*)blockfile->magic));
  printf("blocksize:%d bytes\n",*((int*)blockfile->blocksize));
  blockfile->block=getBlock(f);
  fread(blockfile->space,8,1,f);
  printf("%d\n",*(int *)blockfile->space);
  return blockfile;
}