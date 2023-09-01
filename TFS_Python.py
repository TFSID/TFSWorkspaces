import subprocess

def execute_program1(program_path, parameters):
    try:
        subprocess.run([program_path] + parameters, shell=True, check=True)
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


if __name__ == "__main__":
    program_path1 = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"  # Replace this with the actual path to your first program
    program_path2 = r"C:\Users\tegar\Documents\TFS - Cyber Security\Hacking Tools\Github\dorkScanner\dorkScanner.py"  # Replace this with the actual path to your second program
    program_path3 = r"C:\Users\tegar\Downloads\Programs\osu!install.exe"  # Replace this with the actual path to your third program

    parameters = ["ipconfig"]  # Replace these with the parameters for your first program
    parameters2 = ["param3", "param4"]  # Replace these with the parameters for your second program
    parameters3 = ["param5", "param6"]  # Replace these with the parameters for your third program


    execute_program1(program_path1, parameters)
    # execute_program2(program_path2)
    # execute_program3(program_path3)
