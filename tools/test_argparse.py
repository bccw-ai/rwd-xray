import argparse

parser = argparse.ArgumentParser(description='姓名')
# 字典{integers : 5}, Namespace(integers='5')
#parser.add_argument('integers', type=str, help='传入的数字')  

# [1, 2, 3, 4, 5]
#parser.add_argument('integers', type=int, nargs='+', help='传入的数字')  

# python demo.py --family=张 --name=三
#parser.add_argument('--family', type=str, help='传入的数字')  
#parser.add_argument('--name', type=str, help='传入的数字') 

# 用argparse模块让python脚本接收参数时，对于True/False类型的参数，
# 向add_argument方法中加入参数action=‘store_true’/‘store_false’。
# 顾名思义，store_true就代表着一旦有这个参数，做出动作“将其值标为True”，
# 也就是没有时，默认状态下其值为False。
# 一旦发现“-stock”，arg.stack就返回Ture
parser.add_argument("-stock", action="store_true")
args = parser.parse_args()

if args.stock:
  print('Patch bypassed, making stock RWD')
else:
  #print(args.family+args.name)
  #print(args.stock)
  print('stock:', args.stock)












