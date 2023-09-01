import pyautogui
import time
import keyboard

def send():
    pyautogui.typewrite('ini yang pertama test')
    time.sleep(0.5)
    pyautogui.press('enter')

while True:
    if keyboard.is_pressed('ctrl+alt+s'):
        time.sleep(0.5)
        send()
        