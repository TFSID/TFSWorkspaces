import subprocess
import keyboard
import pyautogui
import os
import pyuac
import time

def execute_program1(program_path):
    try:
        subprocess.run(program_path,)
    except subprocess.CalledProcessError as e:
        print(f"Failed to execute program: {e}")
    except FileNotFoundError:
        print(f"Program not found at the specified path: {program_path}")

def execute_program2(program_path, parameters):
    try:
        subprocess.run([program_path] + parameters, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Failed to execute program: {e}")
    except FileNotFoundError:
        print(f"Program not found at the specified path: {program_path}")

   
    
    

def execute_program3(program_path, parameters):
    try:
        subprocess.run([program_path] + parameters, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Failed to execute program: {e}")
    except FileNotFoundError:
        print(f"Program not found at the specified path: {program_path}")

def print_exit_code(exit_code):
    print(f"Program finished with exit code: {exit_code}")

def jalankan_cmd():
    # os.system("cmd")
    # time.sleep(1)
    
    subprocess.Popen("start cmd", shell=True)
    time.sleep(2)
    keyboard.write('ssh tfs@172.16.1.20')
    time.sleep(0.5)
    # keyboard.press_and_release("enter")
    pyautogui.press('enter')
    
    # os.system("notepad") 
def jalankan_notepad():
    subprocess.Popen("notepad", shell=True)
    

if __name__ == "__main__":
    program_path1 =r"C:\Users\tegar\Documents\TFS - Cyber Security\TFSWorkspaces\automation tools\autorun.dev.txt"

    

    
    jalankan_cmd()
         # Already an admin here.
     # Replace this with the actual path to your first program
    # program_path2 = r"/home/tfs/Github/BlackWidow"  # Replace this with the actual path to your second program
    # program_path3 = r"C:\Users\tegar\Downloads\Programs\osu!install.exe"  # Replace this with the actual path to your third program

    # parameters1 = ["ipconfig"]  # Replace these with the parameters for your first program
    # parameters2 = ["param3", "param4"]  # Replace these with the parameters for your second program
    # parameters3 = ["param5", "param6"]  # Replace these with the parameters for your third program

    

    # execute_program1(program_path1)
    
    
    # execute_program2(program_path2)
    # execute_program3(program_path3)

    print("Thank you for using this program! KONTOL!")
    
