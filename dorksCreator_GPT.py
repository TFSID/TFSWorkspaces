import keyboard
import pyautogui
import time

def send():
    keyword1 = "ecommerce,laptops,iphone,apple,android,gadget"
    scope_keyword = "ecommerce site and online shops"


    pyautogui.typewrite('make ,create wordlist  and rephrase to 40 list with this words '+keyword1+' for searching a '+scope_keyword+' using search engine,help me to optimize the search',0)

    time.sleep(5)
    pyautogui.press('enter')
    pyautogui.typewrite('make ,create wordlist  and rephrase to 40 list with this words '+keyword1+' for searching a '+scope_keyword+' using search engine,help me to optimize the search',0)
   

count = 5
while(count != 0):
    print(count)
    time.sleep(1)
    count -= 1

send()