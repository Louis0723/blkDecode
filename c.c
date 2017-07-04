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
  BYTE space[4];
}BLOCKFILE;

BYTE* varint(FILE *f);
int64_t decodeVarint(BYTE *varint);
BYTE *readLength(int64_t length,FILE *f);
BLOCKFILE *getBlockFile(FILE *f);
BLOCK *getBlock(FILE *f);
BLOCKHEADER *getBlockHeader(FILE *f);
TXINFO *getTxInfo(FILE *f);
TX *getTx(FILE *f);
void getTxInput(FILE *f,TXINPUT *input);
void getTxOutput(FILE *f,TXOUTPUT *output);
void showBlockFile(BLOCKFILE *blockfile);

int main(int argc,char **args)
{ 
  FILE *f=fopen(*(args+1),"rb");
  BLOCKFILE *blockfile;
  long i=0;
  while(feof(f)!=EOF){
    i++;
    blockfile=getBlockFile(f);
    showBlockFile(blockfile);
    printf("\nblock:%lld",i);
    printf("\neof:%d\n",feof(f));
  }
  

  return 0;
}
void showBlockFile(BLOCKFILE *blockfile){
  printf("magic value:");
  for (int i=0;i<4;i++) printf("%x",blockfile->magic[i]);
  printf("\n");
  printf("blocksize:%d bytes\n",*(int*)blockfile->blocksize);
  printf("======block header======\n");
  printf("version:%d\n",*(int*)blockfile->block->blockheader->version );
  printf("previousHash:");
  for(int i=31 ; i>=0 ; i--)printf("%02x",blockfile->block->blockheader->previousHash[i]);
  printf("\nmerkleHash:");
  for(int i=31 ; i>=0 ; i--)printf("%02x",blockfile->block->blockheader->merkleHash[i]);
  printf("\ntimestamp:%d\n",(*(int*)blockfile->block->blockheader->timestamp) );
  printf("bits:%x(%d)\n",*(int*)blockfile->block->blockheader->bits,*(int*)blockfile->block->blockheader->bits);
  printf("nonce:%lld\n",*(int64_t*)blockfile->block->blockheader->nonce);
  printf("========tx=========\n");
  printf("tx count:%lld\n", decodeVarint(blockfile->block->blockbody->txcount) ) ;
  for (int i=0;i<decodeVarint(blockfile->block->blockbody->txcount);i++){
    printf("========tx%d=========\n",i);
    printf("tx version:%d\n", *(int *)blockfile->block->blockbody->txs[i].version );
    printf("tx input count:%lld\n",decodeVarint(blockfile->block->blockbody->txs[i].numinputs) );
    for(int j=0;j<decodeVarint(blockfile->block->blockbody->txs[i].numinputs);j++){
      printf("========tx %d input %d=========\n",i,j);
      printf("previous_output_hash:");
      for(int k=31 ; k >=0 ; k--)printf("%02x",blockfile->block->blockbody->txs[i].inputs[j].previous_output_hash[k]);
      printf("\nprevious_output_index:%ld\n",*(int *)(blockfile->block->blockbody->txs[i].inputs[j].previous_output_index));
      printf("script_lenght:%lld\n",decodeVarint(blockfile->block->blockbody->txs[i].inputs[j].script_length));
      printf("script:");
      for(int k=0 ; k <decodeVarint(blockfile->block->blockbody->txs[i].inputs[j].script_length) ; k++)printf("%02x",blockfile->block->blockbody->txs[i].inputs[j].signature_script[k]);
      printf("\nsequence:%ld\n",*(int *)blockfile->block->blockbody->txs[i].inputs[j].sequence);
    }
    for(int j=0;j<decodeVarint(blockfile->block->blockbody->txs[i].numoutputs);j++){
      printf("========tx %d output %d=========\n",i,j);
      printf("value:%lld\n",*(int64_t *)blockfile->block->blockbody->txs[i].outputs[j].value);
      printf("pk_script_length:%lld\n",decodeVarint(blockfile->block->blockbody->txs[i].outputs[j].pk_script_length) );
      printf("script:");
      for(int k=0;k<decodeVarint(blockfile->block->blockbody->txs[i].outputs[j].pk_script_length);k++)printf("%02x",blockfile->block->blockbody->txs[i].outputs[j].pk_script[k]);
      printf("\n");
    }
    printf("space:%x\n",*(int *)blockfile->space);
    
  }
  
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
  BLOCK *block=malloc(sizeof(BLOCK));
  block->blockheader=getBlockHeader(f);
  block->blockbody=getTxInfo(f);
  return block;
}
BLOCKHEADER *getBlockHeader(FILE *f){
  BLOCKHEADER *blockheader;
  blockheader=malloc(80);
  //printf("======block header======\n");
  fread(blockheader,80,1,f);
  //printf("version:%d\n",*((int*)blockheader->version) );

  //printf("previousHash:");
  for(int i=31 ; i>=0 ; i--){
    //printf("%02x",blockheader->previousHash[i]);
  }
  //printf("\nmerkleHash:");
  for(int i=31 ; i>=0 ; i--){
    //printf("%02x",blockheader->merkleHash[i]);
  }
  //printf("\n");
  //printf("timestamp:%d\n",(*(int*)blockheader->timestamp) );
  //printf("bits:%x(%d)\n",(*(int*)blockheader->bits),(*(int*)blockheader->bits) );
  //printf("nonce:%lld\n",(*(int64_t*)blockheader->nonce) );
  return (blockheader);
}

BLOCKFILE *getBlockFile(FILE *f){
  BLOCKFILE *blockfile=malloc(sizeof(BLOCKFILE));
  blockfile->block=malloc(sizeof(BLOCK));
  fread(blockfile,8,1,f);
  //printf("magic value:%x\n",*((int*)blockfile->magic));
  //printf("blocksize:%d bytes\n",*((int*)blockfile->blocksize));
  blockfile->block=getBlock(f);
  
  if(feof(f)!=EOF)
  fread(blockfile->space,4,1,f);
  //printf("%x\n",*(char *)blockfile->space);
  return blockfile;
}

TXINFO *getTxInfo(FILE *f){
  TXINFO *blockbody=malloc(sizeof(TXINFO));
  blockbody=malloc(sizeof(TXINFO));
  blockbody->txcount=varint(f);
  //printf("========tx=========\n");
  //printf("tx count:%lld\n", decodeVarint(blockbody->txcount) ) ;
  blockbody->txs=malloc(sizeof(TX)*decodeVarint(blockbody->txcount) );

  for (int i=0;i<*(int *)blockbody->txcount;i++){
    fread( &(blockbody->txs[i]),4,1,f);
    //printf("tx version:%d\n", *(int *)blockbody->txs[i].version ) ;

    blockbody->txs[i].numinputs=varint(f);
    //printf("tx input count:%lld\n",decodeVarint(blockbody->txs[i].numinputs) );
    
    blockbody->txs[i].inputs=malloc(sizeof(TXINPUT)*decodeVarint(blockbody->txs[i].numinputs) );
    for(int j=0;j<decodeVarint(blockbody->txs[i].numinputs);j++){
      getTxInput(f,&blockbody->txs[i].inputs[j]);
    }

    blockbody->txs[i].numoutputs=varint(f);
    //printf("tx output count:%lld\n",decodeVarint(blockbody->txs[i].numoutputs) );
    blockbody->txs[i].outputs=malloc(sizeof(TXOUTPUT)*decodeVarint(blockbody->txs[i].numoutputs) );
    for(int j=0;j<decodeVarint(blockbody->txs[i].numoutputs);j++){
      getTxOutput(f,&blockbody->txs[i].outputs[j]);
    }
  }
  return blockbody;
}


void getTxInput(FILE *f,TXINPUT *input){
  //printf("========tx input=========\n");
  //printf("previous_output_hash:");
  fread(input->previous_output_hash,32,1,f);
  for(int i=31 ; i>=0 ; i--){
    //printf("%02x",input->previous_output_hash[i]);
  }
  //printf("\n");
  fread(input->previous_output_index,4,1,f);
  //printf("previous_output_index:%ld\n",*(int *)(input->previous_output_index));
  input->script_length=varint(f);
  //printf("script_lenght:%lld\n",decodeVarint(input->script_length));
  input->signature_script=readLength(decodeVarint(input->script_length),f);
  //printf("script:");
  for(int i=0;i<*(int *)(input->script_length);i++)
  {
    //printf("%02x",input->signature_script[i]);
  }
  //printf("\n");
  fread( input->sequence,4,1,f);
  //printf("sequence:%ld\n",*(int *)input->sequence);
}

void getTxOutput(FILE *f,TXOUTPUT *output){
  //printf("========tx output========\n");
  fread(output->value,8,1,f);
  //printf("value:%lld\n",*(long long int *)output->value);
  output->pk_script_length=varint(f);
  //printf("pk_script_length:%lld\n",decodeVarint(output->pk_script_length) );
  output->pk_script=readLength(decodeVarint(output->pk_script_length),f);
  //printf("script");
  for(int i=0;i<*(int *)output->pk_script_length;i++)
  {
    //printf("%02x",output->pk_script[i]);
  }
  //printf("\n");
}