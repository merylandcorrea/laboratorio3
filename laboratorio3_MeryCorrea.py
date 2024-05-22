#Nombre : Mery Land Correa Barrera
#Codigo: 200108657

from Crypto.Hash import SHA3_512
from Crypto.Random import get_random_bytes
import pandas as pd
import threading

#hallar salt, password en el .csv
user = 'barreralm'
df = pd.read_csv('C:/Users/Meryl/Desktop/laboratorio3_MeryCorrea/laboratorio3/password_database_ED2.csv')
for index, row in df.iterrows():
    if row['username']==user:
       salt = row['salt']
       passw = row['password']
       break
print('user: ',user,'salt: ', salt,'password: ', passw)


#Llenar la lista possible_pwd con todos los datos de rockyou.txt
def read_file_to_list(file_path):
    #Lee el archivo y guarda cada línea en una lista, eliminando espacios en blanco.
    possible_pwd = []
    with open(file_path, 'r', encoding='utf-8' , errors='ignore') as file:
        for line in file:
            possible_pwd.append(line.strip())
    return possible_pwd

file_path = 'C:/Users/Meryl/Desktop/laboratorio3_MeryCorrea/laboratorio3/rockyou.txt'
possible_pwd = read_file_to_list(file_path)

i=0
for p_pwd in possible_pwd:
    for pep in range(256):
        H = SHA3_512.new()

        password_b = bytes (p_pwd, 'utf-8')
        H.update(password_b)

        pep_b = pep.to_bytes(1,'big')
        H.update(pep_b)

        s_b =bytes.fromhex(salt)
        H.update(s_b)

        pwd_h = H.hexdigest()

        if pwd_h == passw:
            print(p_pwd)
        else:
            print(i,' aun no se encuentra')
    i += 1


