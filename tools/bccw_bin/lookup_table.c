#include <stdio.h>


#define uint unsigned int

int find_in_table_bsearch(short val,int keys,int number_of_keys)
{
  int iVar1;
  int iVar2;
  int tmp_key_idx;
  int iVar3;
  
  /* find_in_table_binary_search */
  number_of_keys = number_of_keys + -1;
  tmp_key_idx = (int)(char)((uint)number_of_keys >> 8);
  iVar3 = tmp_key_idx + (uint)(tmp_key_idx < 0);
  iVar1 = 0;
  while ('\x01' < (char)((uint)tmp_key_idx >> 8)) {
    tmp_key_idx = (int)(char)((uint)(iVar3 >> 1) >> 8);
    iVar2 = tmp_key_idx;
    if (val >> 0xf < *(short *)(keys + tmp_key_idx * 2)) {
      iVar2 = iVar1;
      number_of_keys = tmp_key_idx;
    }
    iVar3 = (int)(char)((uint)(iVar2 + number_of_keys) >> 8);
    iVar3 = iVar3 + (uint)(iVar3 < 0);
    tmp_key_idx = number_of_keys - iVar2;
    iVar1 = iVar2;
  }
  return iVar3 >> 1;
}

int table_lookup(short val,short *key,short *values,uint number_of_keys)
{
  short val_00;
  uint idx;
  int ret;
  int key_diff;
  int val_local;
  
  //val_00 = (short)((uint)val >> 0x10);
  val_00 = (short)((uint)val);
  val_local = (int)val_00;
  if (*key < val_local) {
    ret = (number_of_keys & 0xff) - 1;
    if (val_local < key[ret]) {
      idx = find_in_table_bsearch(val_00,key,number_of_keys & 0xff);
      idx = idx & 0xff;
      ret = (int)values[idx];
      key_diff = (int)key[idx + 1] - (int)key[idx];
      if (key_diff == 0) {
        ret = ret + values[idx + 1];
                    /* 如果这两个密钥是相同的，取平均值 */
        ret = (int)(ret + (uint)(ret < 0)) >> 1;
      }
      else {
                    /* 插补 */
        ret = ((val_local - (int)key[idx]) * (values[idx + 1] - ret)) / key_diff + ret;
      }
                    /* 极限检查 */
      if (ret < -0x7fff) {
        ret = -0x7fff;
      }
      else {
        if (0x7fff < ret) {
          ret = 0x7fff;
        }
      }
    }
    else {
      ret = (int)values[ret];
    }
  }
  else {
    ret = (int)*values;
  }
  return ret;
}

short idx_all[63] = {
  0x0,   0xDB,  0x1BB,  0x296,
0x377,  0x454,  0x532,  0x610,
0x67F,    0x0,   0xDB,  0x1BB,
0x299,  0x377,  0x454,  0x532,
0x610,  0x67F,    0x0,   0xDE,
0x1B5,  0x275,  0x356,  0x454,
0x51C,  0x610,  0x6EE,    0x0,
 0xDE,  0x1B5,  0x275,  0x356,
0x454,  0x51C,  0x610,  0x6EE,
  0x0,   0xDE,  0x1B5,  0x275,
0x356,  0x454,  0x51C,  0x610,
0x6EE,    0x0,   0xDE,  0x1B5,
0x275,  0x356,  0x454,  0x51C,
0x610,  0x6EE,    0x0,   0xDE,
0x1BB,  0x299,  0x377,  0x454,
0x532,  0x610,  0x67F    
};

short val_all[63] = {
   0x0,  0x500,  0xC52,  0xE80,
0x1200, 0x1300, 0x134D, 0x1380,
0x1400,    0x0,  0x4C0,  0xB80,
0x1040, 0x1240, 0x1340, 0x1380,
0x13C0, 0x1400,    0x0,  0x6B3,
 0xBF8,  0xEBB, 0x1078, 0x1200,
0x1317, 0x1400, 0x1400,    0x0,
 0x6B3,  0xBF8,  0xEBB, 0x1078,
0x1200, 0x1317, 0x1400, 0x1400,
   0x0,  0x6B3,  0xBF8,  0xEBB,
0x1078, 0x1200, 0x1317, 0x1400,
0x1400,    0x0,  0x6B3,  0xBF8,
 0xEBB, 0x1078, 0x1200, 0x1317,
0x1400, 0x1400,    0x0,  0x6E1,
 0xC9A, 0x1000, 0x1100, 0x1200,
0x129A, 0x134D, 0x1400
};


short idx_u[9] = {
  0x0,   0xDB,  0x1BB,  0x296,
0x377,  0x454,  0x532,  0x610,
0x67F};

short val_u[9] = {
   0x0,  0x500,  0xC52,  0xE80,
0x1200, 0x1300, 0x134D, 0x1380,
0x1400 };


short idx[9] = {
  0x0,   0xDE,  0x14d,  0x1ef,
0x290,  0x377,  0x454,  0x610,
0x6ee};

short val[9] = {
   0x0,  0x917,  0xdc5, 0x1017,
0x119f, 0x140b, 0x1680, 0x1680,
0x1680 };

void lt(short in)
{
  short ret = table_lookup(in, idx_all, val_all, 9);
  printf("0x%x -> 0x%x\n", in, ret);
}

int main()
{
  lt(0x100);
  lt(0x700);
  lt(0x2000);

  return 0;
}
