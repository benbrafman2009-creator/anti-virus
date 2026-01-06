from Desktop.Lib.test.test_pydoc.pydocfodder import count
from pathlib import Path
import requests
import time
import tkinter
import customtkinter
import threading
def thread_download_file():
    download = threading.Thread(target=scan_file)
    download.start()
#system settings
customtkinter.set_appearance_mode("System")
customtkinter.set_default_color_theme("dark-blue")
#app frame(size)
app = customtkinter.CTk()# a var for the app
app.geometry("720x480")
app.title("virus detector")
#Ui Elements
title = customtkinter.CTkLabel(app,text="Insert a folder")
title.pack(padx=10,pady=10)
#link input
url_var = tkinter.StringVar()
link = customtkinter.CTkEntry(app,width=350,height=40,textvariable=url_var)
link.pack()
finished = customtkinter.CTkLabel(app,text="")
finished.pack()
#download button
send = customtkinter.CTkButton(app,text="send",command=thread_download_file )
send.pack(padx = 10,pady=10)
file_loder = customtkinter.CTkLabel(app,text="")
file_loder.pack(padx=10)
load_bar_text = customtkinter.CTkLabel(app,text="0%")
load_bar_text.pack()
load_bar = customtkinter.CTkProgressBar(app,width=300)
load_bar.set(0)
load_bar.pack(pady=5)
mal = customtkinter.CTkLabel(app, text="")
undetected = customtkinter.CTkLabel(app, text="")
sus = customtkinter.CTkLabel(app, text="")
harmless = customtkinter.CTkLabel(app, text="")

mal.pack()
undetected.pack()
sus.pack()
harmless.pack()

def per_cal(fileNum,fileAmount):
    per = str(fileNum / fileAmount * 100)
    if per != "100.0":
        load_bar_text.configure(text=f"{(per[:3])}%")
    else:
        load_bar_text.configure(text="Download completed",text_color="green")
    load_bar_text.update()
    load_bar.set(float(per)/100)
def dir_packages(path):
    p = Path(path)
    if p.is_file():
        return [str(p)],1
    list_files = [str(f) for f in p.rglob("*") if f.is_file()]
    length = len(list_files)
    return list_files,length

def scan_file():
    files_before_process = link.get()
    files,length = dir_packages(files_before_process)
    num_file = 0
    url = "https://www.virustotal.com/api/v3/files"
    headers = {
        "x-apikey": "e74b7c3eeb069dd64a4d6acf190ebba937e99f1791a8d82890e4af162c636cf6"
    }

    for f in files:
        num_file+=1
        print(f"\nScanning: {f}")
        try:
            # Submit file for scanning
            with open(f, "rb") as file:
                response = requests.post(
                    url,
                    headers=headers,
                    files={"file": file}
                )

            if response.status_code == 200:
                result = response.json()
                analysis_id = result['data']['id']
                file_loder.configure(text=f"Submitted successfully file {f}",text_color="green")
                per_cal(num_file,length)
                diagnose_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
                diagnose_data = requests.get(diagnose_url,headers=headers)
                diagnose_data = diagnose_data.json()
                args = diagnose_data["data"]["attributes"]["stats"]
                malicious = args["malicious"]
                undetected2 = args["undetected"]
                suspicious = args["suspicious"]
                harmless2 = args["harmless"]
                mal.configure(text="malicious:" + str(malicious),text_color="red")
                undetected.configure(text="undetected:" + str(undetected2), text_color="white")
                sus.configure(text="suspicious:" + str(suspicious),text_color="orange")
                harmless.configure(text=f"harmless:{harmless2}",text_color="green")
            else:
                file_loder.configure(text=f"Error from the server! for {f}",text_color="red")
                break
            time.sleep(10)
        except FileNotFoundError:
            file_loder.configure(text=f"file not found {f}",text_color="red")
            break
        except Exception as e:
            file_loder.configure(text=f"Error in the file {f}",text_color="red")
            break
    if num_file == 0:
        file_loder.configure(text=f"No file detected", text_color="red")


def main():
    app.mainloop()



if __name__ == "__main__":
    main()