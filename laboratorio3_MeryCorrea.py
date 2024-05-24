#Nombre : Mery Land Correa Barrera
#Codigo: 200108657

from Crypto.Hash import SHA3_512
from Crypto.Random import get_random_bytes
import pandas as pd
import threading

# Variable de condición para detener la búsqueda
password_found_event = threading.Event()

#hallar salt, password en el .csv
"""
user = 'barreralm'
df = pd.read_csv('C:/Users/Meryl/Desktop/laboratorio3_MeryCorrea/password_database_ED2.csv')
for index, row in df.iterrows():
    if row['username']==user:
       salt = row['salt']
       passw = row['password']
       break
print('user: ',user,'salt: ', salt,'password: ', passw)
"""
user = "edangulo"
salt= "dc9b55a30b2aa326b23f8d603eca9b64"
passw = "35a7b194c19915e7ff698a8656da1fd68ff73a0adc36cc4bfb1a2dd90333d91b5689075d0acab015c9c109082b1cf1d607da13a224b058b0749ef377f1234434"


"""
#Llenar la lista possible_pwd con todos los datos de rockyou.txt
def read_file_to_list(file_path):
    #Lee el archivo y guarda cada línea en una lista, eliminando espacios en blanco.
    possible_pwd = []
    with open(file_path, 'r', encoding='utf-8' , errors='ignore') as file:
        for line in file:
            possible_pwd.append(line.strip())
    return possible_pwd"""

# Llenar la lista possible_pwd con todos los datos de rockyou.txt
def read_file_to_list(file_path, start_line, end_line):
    possible_pwd = []
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
        for i, line in enumerate(file):
            if i >= 156000:  # Detiene la lectura después de las primeras 1434156 líneas
                break
            if start_line <= i < end_line:
                possible_pwd.append(line.strip())
    return possible_pwd

file_path = 'C:/Users/Meryl/Desktop/laboratorio3_MeryCorrea/rockyou.txt'
#possible_pwd = read_file_to_list(file_path)


# Función para la búsqueda de contraseñas
def search_password(user, salt, passw, possible_pwd):
  i=0
  for p_pwd in possible_pwd:
    if password_found_event.is_set():  # Verificar si la contraseña ya fue encontrada
            break
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
            print("--------------------------------------------",p_pwd,"--------------------------------------------")
            password_found_event.set()  # Establecer la variable de condición para detener la búsqueda
            return
    print(i,' Buscando.....')
    i += 1
if not password_found_event.is_set():
    print(f"No se encontró ninguna contraseña para el usuario {user}")          
        


num_threads = 10
total_lines = sum(1 for line in open(file_path, 'r', encoding='utf-8', errors='ignore'))
lines_per_thread = total_lines // num_threads

# Definir una lista para almacenar los hilos
threads = []

# Función para iniciar el hilo de búsqueda de contraseñas
def start_search_thread(user, salt, passw, start_line, end_line):
    possible_pwd = read_file_to_list(file_path, start_line, end_line)
    t = threading.Thread(target=search_password, args=(user, salt, passw, possible_pwd))
    t.start()
    threads.append(t)

# Lanzar múltiples hilos para realizar la búsqueda de contraseñas 
for i in range(num_threads):
    start_line = i * lines_per_thread
    end_line = start_line + lines_per_thread if i < num_threads - 1 else total_lines
    start_search_thread(user, salt, passw, start_line, end_line)

# Esperar a que todos los hilos terminen
for t in threads:
    t.join()

