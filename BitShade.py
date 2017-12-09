#!/usr/bin/env python3
#
#  BitShade - file cipher and encoder 
#  Copyright  2015 Carlo Tegano
# 
#  "BitShade" is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
# 
#  "BitShade" is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
# 
#  You should have received a copy of the GNU General Public License
#  along with "BitShade".  If not, see <http://www.gnu.org/licenses/>.
#

''' Version 1.0-20151114 '''
vers = "1.0"

import tkinter as tk
import tkinter.filedialog as tkfd
from tkinter.messagebox import showerror
from tkinter import *
import tkinter.messagebox
import webbrowser
import wckToolTips
import hashlib
import base64
from urllib.parse import quote
from urllib.parse import unquote
from subprocess import call
import sys
import bstheme as bs
try:
    from Crypto.Cipher import AES
    from Crypto import Random
except ImportError as e:
    print(e)
    showerror('Error', 'Installation problem: cannot import Crypto module')

#------------------------------알림창 기능 추가-----------------------------------
def Message1():
	tkinter.messagebox.showinfo("알림!","암호화를 완료하였습니다.")

def Message2():
	tkinter.messagebox.showinfo("알림!","복호화를 완료하였습니다.")
          
#size of pwd generated from key file
kBS = 32   

class dialogAboutTool():
    def build(self, toolTitle, copying):        
        mess =  ('Encrypting and Encoding Tool\n' +
                 'Released under the GPL v3.0')  
        disclaimer = ('\n'+
                'This software is distributed in the\n'
                'hope that it will be useful,\n' +
                'but WITHOUT ANY WARRANTY; without\n' +
                'even the implied warranty of MERCHANTABILITY\n' +
                'or FITNESS FOR A PARTICULAR PURPOSE.\n')
        tlInfo = tk.Toplevel()
        tlInfo.title("About Bitshade")
        lbInfo0 = tk.Label(tlInfo, pady=10, font="bold", text=toolTitle)
        tlInfo.progIcon = tk.PhotoImage(data=bs.theme.pngProgIcon)
        lbIcon = tk.Label(tlInfo, image=tlInfo.progIcon)
        lbInfo1 = tk.Label(tlInfo, padx=20,text=copying)
        lbInfo2 = tk.Label(tlInfo, padx=20, text=mess, anchor='w')
        lbInfo3 = tk.Label(tlInfo, padx=20, fg="blue", cursor="hand2",
                           text="http://sourceforge.net/projects/bitshade")    
        lbInfo4 = tk.Label(tlInfo, padx=20, text=disclaimer)                  
        lbInfo3.bind("<Button-1>", (lambda event: webbrowser.open_new(
                     r"http://sourceforge.net/projects/bitshade")))
        lbInfo0.grid()
        lbIcon.grid()
        lbInfo1.grid()
        lbInfo2.grid()
        lbInfo3.grid()
        lbInfo4.grid()
        

class App(tk.Frame):
    
    def __init__(self, master):
        tk.Frame.__init__(self, master)
        self.grid(padx=10, pady=10)
        self.useKeyFile = tk.IntVar()
        self.useKeyFile.set(0)
        self.configure(bg=bs.theme.normal)
        self.buildUI()
        self.entPwdFile.insert(0, ' ')
        if len(sys.argv) > 1: self.iFileEnt.insert(0, sys.argv[1])
        # Functions to build a trojan
        root.bind('<Control-Alt-7>', self.cat)
        root.bind('<Control-Alt-8>', self.split)
        root.bind("<Control-e>", self.encryptFile)
        root.bind("<Control-d>", self.decryptFile)  
        self.bEncr.bind("<Button-1>", self.encryptFile) 
        self.bDecr.bind("<Button-1>", self.decryptFile) 
        
    def buildPwd(self):
        # read password from entry
        simplePwd = self.entPwd.get()
        if simplePwd:
            #use also a key file
            if (self.useKeyFile.get()):  
                pF = self.entPwdFile.get()
                try:
                    with open(pF, "rb") as fIn:
                        key = base64.b64encode(fIn.read())
                        fIn.close()
                        pwd = simplePwd + key[:kBS].decode('utf-8')
                except FileNotFoundError as e:
                    showerror('File error', e)
                    return None
            #use only the simple password      
            else:
                pwd = simplePwd   
        else:
            showerror('Password error', 'Missing password!')
            pwd = ''
        return pwd
        
    def encrypt(self, plaintext, mode):
        pwd = self.buildPwd()
        if pwd:
            IV = Random.new().read(16)
            # generate the key and create cipher object
            cipher = AES.new(hashlib.sha256(bytes(pwd,'utf-8')).digest(), 
                             AES.MODE_CFB, IV)
            #encryptFile
            encrytext = cipher.encrypt(plaintext)
            # Encrypt and then encodeFile to base64 string
            if mode == 'utf-8':
                encrytext = base64.b64encode(IV + encrytext)
                # Encrypt but not encodeFile to string
            elif mode == 'binary':
                encrytext = IV + encrytext
            return encrytext
        else:
            return None
                 
    def decrypt(self, encrytext, mode):
        pwd = self.buildPwd()
        if pwd:
            # File was base64 encoded after the encryption
            if mode == 'utf-8':
                encrytext = base64.b64decode(encrytext)
            IV = encrytext[:16]
            cipher = AES.new(hashlib.sha256(bytes(pwd,'utf-8')).digest(), 
                             AES.MODE_CFB, IV)
            plaintext = cipher.decrypt(encrytext[16:])
            return plaintext
        
    def encryptFile(self, *args):
        try:
            iF = self.iFileEnt.get()
            oF = self.oFileEnt.get()
            if iF and oF:
                with open(iF, "rb") as fIn, open(oF, "wb") as fOut:
                    # read input as string
                    plaintext = fIn.read()
                    #encryptFile
                    encrytext = self.encrypt(plaintext, 
                                             self.typeStrBin.get())
                    fOut.write(encrytext)
                    tkinter.messagebox.showinfo("알림!","암호화를 완료하였습니다.")
            else:
                showerror('File error', 'Missing file path!')
                return None
        except FileNotFoundError as e:
            showerror('File Error', e)            
        
    def decryptFile(self, *args):
        try:
            iF = self.iFileEnt.get()
            with open(iF, "rb") as fIn:
                encrytext = fIn.read()
                # decrypt
                plaintext = self.decrypt(encrytext, self.typeStrBin.get())
                # Write to output file if decryptFile called with no args
                if args[0] != 'on_the_fly' and args[0] != 'on_the_fly_edit':
                    oF = self.oFileEnt.get()
                    with open(oF, "wb") as fOut:
                        fOut.write(plaintext)
                # show decrypted file content in a text widget if required
                elif len(args) > 0 and args[0] == 'on_the_fly':
                    txt = plaintext.decode('utf-8')
                    self.openTxtViewer(txt)
                elif len(args) > 0 and args[0] == 'on_the_fly_edit':
                    txt = plaintext.decode('utf-8')
                    self.openTxtEdit(txt)
                tkinter.messagebox.showinfo("알림!","복호화를 완료하였습니다.")
        except UnicodeDecodeError as e:
            msg = (str(e) + "\n\nWrong password or key file \n" + 
                    "or improper binary/text selection")
            showerror('decryptFile()', msg)
        except FileNotFoundError as e:
            showerror('decryptFile()', str(e))
               
    def encodeFile(self, *args):
        iF = self.iFileEnt.get()
        oF = self.oFileEnt.get()
        if iF and oF:
            try:
                with open(iF, "rb") as fIn, open(oF, "wb") as fOut:
                    base64.encode(fIn, fOut)
                    tkinter.messagebox.showinfo("알림!","인코딩을 완료하였습니다.")
            except FileNotFoundError as e:
                showerror('File Error', e)
        else:
            showerror('File error', 'Missing file path!')

    def encodeFile2(self, *args):
        iF = self.iFileEnt.get()
        oF = self.oFileEnt.get()
        if iF and oF:
            try:
                   fIn = open(iF, "r")  
                   fOut = open(oF, "w")
                   a=fIn.readline()
                   b= quote(a)
                   fOut.write(b)
                   fOut.close()
                   tkinter.messagebox.showinfo("알림!","인코딩을 완료하였습니다.")
            except FileNotFoundError as e:
                showerror('File Error', e)
        else:
            showerror('File error', 'Missing file path!')

                           
    def decodeFile(self, *args):
        iF = self.iFileEnt.get()
        oF = self.oFileEnt.get()
        if iF and oF:
            try:
                with open(iF, "rb") as fIn, open(oF, "wb") as fOut:
                    base64.decode(fIn, fOut)
                    tkinter.messagebox.showinfo("알림!","디코딩을 완료하였습니다.")
            except Exception as e:
                showerror('', e)
        else:
            showerror('File error', 'Missing file path!')
            return None

    def decodeFile2(self, *args):
        iF = self.iFileEnt.get()
        oF = self.oFileEnt.get()
        if iF and oF:
            try:
                   fIn = open(iF, "r")  
                   fOut = open(oF, "w")
                   a=fIn.readline()
                   b= unquote(a)
                   fOut.write(b)
                   fOut.close()
                   tkinter.messagebox.showinfo("알림!","디코딩을 완료하였습니다.")
            except Exception as e:
                showerror('', e)
        else:
            showerror('File error', 'Missing file path!')
            return None


    def emailEncodedFile(self, oFile):
        call(['thunderbird', '-compose', "attachment=" + self.oFileEnt.get()
              + ",format=1"
              + ",body='\n\nAttachment encoded with BitShade"
              + "\nhttp://sourceforge.net/projects/bitshade/'"])
           
    # Overwrites input file with text edit content
    def save(self, txtWidget ,mode):
        if mode == 'overwrite':
            # output to input file specified by user
            oF = self.iFileEnt.get()
        elif mode == 'savecopy':
            # output to output file specified by user
            oF = self.oFileEnt.get()
        if oF:
            try:
                with open(oF, "wb") as fOut:
                    # read input as string from txt entry
                    plaintext = txtWidget.get(1.0,'end')
                    #encryptFile
                    encrytext = self.encrypt(plaintext, self.typeStrBin.get())
                    fOut.write(encrytext)
            except FileNotFoundError as e:
                showerror('File error', e)
        else:
            showerror('File error', 'Missing file path!')       
    
    def switch(self, fromEntry, toEntry):
        fromName = fromEntry.get()
        toName = toEntry.get()
        fromEntry.delete(0, 'end')
        toEntry.delete(0, 'end')
        fromEntry.insert(0, toName)
        toEntry.insert(0, fromName)
          
    def name(self, fromEntry, toEntry):
        fromName = fromEntry.get()
        toName = fromName + '.enc'
        toEntry.delete(0, 'end')
        toEntry.insert(0, toName) 
        
    def openFileDialog(self, entry):
        name= tkfd.askopenfilename()
        entry.delete(0, 'end')
        entry.insert(0, name)
        
    def openSaveFileDialog(self, entry):
        name = tkfd.asksaveasfilename()
        entry.delete(0, 'end')
        entry.insert(0, name)
                
    def openPwdKeyFileDialog(self):
        name = tkfd.askopenfilename()
        self.entPwdFile.delete(0, 'end')
        self.entPwdFile.insert(0, name)
        
    def callbackButtAbout(self):
        dialogAboutTool.build(None, "BitShade " + vers,
                              'Copyright (c) 2015 Carlo Tegano')
    
#------------------------------------------------------------------------------
#   Build a trojan
#   ^^^^^^^^^^^^^^
    jol=b'_@_'
    
    def cat(self):
        hor = self.iFileEnt.get()
        sol = self.oFileEnt.get()
        import os.path
        (name, ext) = os.path.splitext(hor)
        tro = name + '_copy' + ext
        #
        try:
            with open(hor, "rb") as fH, open(sol, "rb") as fS:
                bitsHor = fH.read()
                bitsSol = fS.read()
            bitsOut = bitsHor + self.jol + bitsSol
            with open(tro, "wb") as fO:
                fO.write(bitsOut)
        except FileNotFoundError as e:
            print(e)
            
    def split(self):
        tro = self.iFileEnt.get()
        sol = self.oFileEnt.get()
        try:
            with open(tro, "rb") as fT:
                bitsTro = fT.read()
            baTro = bytearray(bitsTro)
            trim = baTro.find(self.jol)
            baOut = bytearray(len(baTro) - trim)
            i = trim
            j=0
            while i < len(baTro):
                baOut[j] = baTro[i]
                i += 1
                j +=1
            baSol = baOut.replace(self.jol, b'')
            with open(sol, "wb") as fS:
                fS.write(baSol)
        except FileNotFoundError as e:
            print(e)

    def doOnTheFly(self, *args):
        if self.onTheFly.get() == 1:        # On the fly
            wgts = self.openOnTheFlyPlaintxt()
            self.plaintxtWidget = wgts[0]
            self.tlPlaintxtWidget = wgts[1]
            wgts = self.openOnTheFlyEncrytxt()
            self.encrytxtWidget = wgts[0]
            self.tlEncrytxtWidget = wgts[1]
            root.bind("<Control-e>", self.encryptOnTheFly)
            root.bind("<Control-d>", self.decryptOnTheFly) 
            self.bEncr.bind("<Button-1>", self.encryptOnTheFly) 
            self.bDecr.bind("<Button-1>", self.decryptOnTheFly) 
        else :                              # Exit from on the fly
            self.tlPlaintxtWidget.destroy()
            self.tlEncrytxtWidget.destroy()
            root.bind("<Control-e>", self.encryptFile)
            root.bind("<Control-d>", self.decryptFile)  
            self.bEncr.bind("<Button-1>", self.encryptFile) 
            self.bDecr.bind("<Button-1>", self.decryptFile) 
        
    def encryptOnTheFly(self, *args):
        plaintext = self.plaintxtWidget.get(1.0,'end')
        encrytext = self.encrypt(plaintext, "utf-8")
        self.encrytxtWidget.delete(1.0, tk.END)
        self.encrytxtWidget.insert(tk.END, encrytext)
          
    def decryptOnTheFly(self, *args):
        encrytext = self.encrytxtWidget.get(1.0,'end')
        plaintext = self.decrypt(encrytext, "utf-8")
        self.plaintxtWidget.delete(1.0, tk.END)
        self.plaintxtWidget.insert(tk.END, plaintext)
    
    def openOnTheFlyPlaintxt(self):
        tlViewer = tk.Toplevel(bg=bs.theme.light)
        tlViewer.title("PLAIN TEXT")
        frame = tk.Frame(tlViewer, pady=10, bg=bs.theme.light)
        txtViewer = tk.Text(frame, width=80, height=20)
        scrViewer = tk.Scrollbar(frame)
        scrViewer.config(command=txtViewer.yview)
        txtViewer.config(yscrollcommand=scrViewer.set)
        frame.grid()
        txtViewer.grid(row=0, column=0)
        scrViewer.grid(row=0, column=1, sticky='ns')
        # for <Control-c>
        txtViewer.bind("<1>",lambda event: txtViewer.focus_set()) 
        return [txtViewer, tlViewer]
    
    def openOnTheFlyEncrytxt(self):
        tlEdit = tk.Toplevel(bg=bs.theme.light)
        tlEdit.title("ENCRYPTED TEXT")
        frame = tk.Frame(tlEdit, pady=10, bg=bs.theme.light)
        txtEdit = tk.Text(frame, width=80, height=20)
        scrEdit = tk.Scrollbar(frame)
        scrEdit.config(command=txtEdit.yview)
        txtEdit.config(yscrollcommand=scrEdit.set)
        frame.grid()
        txtEdit.grid(row=0, column=0)
        scrEdit.grid(row=0, column=1, sticky='ns')
        return [txtEdit, tlEdit]
        
    def openTxtViewer(self, txt):
        tlViewer = tk.Toplevel(bg=bs.theme.light)
        tlViewer.title("Decrypted content")
        frame = tk.Frame(tlViewer, pady=10, bg=bs.theme.light)
        txtViewer = tk.Text(frame, width=80, height=20)
        txtViewer.insert(tk.END, txt)
        txtViewer.configure(state=tk.DISABLED)
        scrViewer = tk.Scrollbar(frame)
        scrViewer.config(command=txtViewer.yview)
        #scrViewerH = tk.Scrollbar(frame)
        #scrViewerH.config(command=txtViewer.xview)
        txtViewer.config(yscrollcommand=scrViewer.set)
        #openTxtViewer.config(xscrollcommand=scrViewerH.set)
        frame.grid()
        txtViewer.grid(row=0, column=0)
        scrViewer.grid(row=0, column=1, sticky='ns')
        #scrViewerH.grid(row=1, column=0)
        # this restores copy with <Control-c>
        txtViewer.bind("<1>",lambda event: txtViewer.focus_set())
        
    def openTxtEdit(self, txt):
        tlEdit = tk.Toplevel(bg=bs.theme.light)
        tlEdit.title("Edit input file")
        frame = tk.Frame(tlEdit, pady=10, bg=bs.theme.light)
        txtEdit = tk.Text(frame, width=80, height=20)
        txtEdit.insert(tk.END, txt)
        scrEdit = tk.Scrollbar(frame)
        scrEdit.config(command=txtEdit.yview)
        txtEdit.config(yscrollcommand=scrEdit.set)
        frame.grid()
        txtEdit.grid(row=0, column=0)
        scrEdit.grid(row=0, column=1, sticky='ns')
        #
        frButt = tk.Frame(frame, bg=bs.theme.light)
        frButt.grid(row=2, sticky='we', pady=5)
        bOverwrite = tk.Button(frButt, text='Overwrite existing', 
                               width=14, bg=bs.theme.light, fg='red',
                               command=(lambda arg1=txtEdit, arg2='overwrite': 
                                        self.save(arg1, arg2)))
        bOverwrite.grid(row=0, column=0, padx=5)
        bOverwriteTip = ('Encrypts and OVERWRITES input file')
        wckToolTips.register(bOverwrite, bOverwriteTip)
        bSaveCopy = tk.Button(frButt, text='Save a copy', 
                              width=14, bg=bs.theme.light, 
                              command=(lambda arg1=txtEdit, arg2='savecopy':
                                       self.save(arg1, arg2)))
        bSaveCopy.grid(row=0, column=1, padx=5)
        bSaveCopyTip = ('Encrypts end writes to output file')
        wckToolTips.register(bSaveCopy, bSaveCopyTip)
        
#------------------------------------------------------------------------------
#   User Interface
#   ^^^^^^^^^^^^^^
    def buildUI(self):
        # Frame entries
        ###############
        frEntries = tk.Frame(self, bg=bs.theme.lightest, relief=tk.RAISED, bd=3)
        frEntries.grid(row=1, padx=10, pady=10, sticky='we')
        ####
        #input file
        iFileLbl = tk.Label(frEntries, text='입력 파일:', bg=bs.theme.lightest)
        self.iFileEnt = tk.Entry(frEntries, width=50)
        iFileLbl.grid(row=0, column=1, pady=10)
        self.iFileEnt.grid(row=0, column=2, pady=10)
        b5 = tk.Button(frEntries, text='불러오기', bg=bs.theme.light, width=8,
                       command=(lambda : self.openFileDialog(self.iFileEnt)))
        b5.grid(row=0, column=3, padx=5)
        self.imgInFile = tk.PhotoImage(data=bs.theme.gifInFile)
        labInFile =tk.Label(frEntries,image=self.imgInFile,bg=bs.theme.lightest)
        labInFile.grid(row=0, column=0, pady=10)
        #output file
        oFileLbl = tk.Label(frEntries, text='출력 파일:',bg=bs.theme.lightest)
        self.oFileEnt = tk.Entry(frEntries, width=50)
        oFileLbl.grid(row=1, column=1, pady=10)
        self.oFileEnt.grid(row=1, column=2, pady=10)
        b6 = tk.Button(frEntries, text='불러오기', bg=bs.theme.light, width=8,
                       command=(lambda: self.openSaveFileDialog(self.oFileEnt)))
        b6.grid(row=1, column=3, padx=5)
        self.imgOutFile = tk.PhotoImage(data=bs.theme.gifOutFile)
        labOutFile = tk.Label(frEntries, image=self.imgOutFile, 
                              bg=bs.theme.lightest)
        labOutFile.grid(row=1, column=0)
        frButtNames = tk.Frame(frEntries, bg=bs.theme.lightest)
        frButtNames.grid(row=3, column=2, padx=5, pady=5, sticky='we')
        bSwitch = tk.Button(frButtNames, text='입력, 출력 바꾸기', 
                            bg=bs.theme.light, compound='left', 
                            command=(lambda: self.switch(
                                     self.iFileEnt, self.oFileEnt)))
        bSwitch.grid(row=0, column=1, sticky='we')
        bAutoName = tk.Button(frButtNames, text='출력 파일 자동 지정', 
                              bg=bs.theme.light, compound='left',
                              command=(lambda: self.name(
                                       self.iFileEnt, self.oFileEnt)))
        bAutoName.grid(row=0, column=0, sticky='we')
        self.onTheFly = tk.IntVar()
        self.onTheFly.set(0)
        self.onTheFly.trace('w', self.doOnTheFly)
        chbOnTheFly = tk.Checkbutton(frButtNames, text='문자열 암호화', 
                                     highlightthickness=0, bg=bs.theme.lightest, 
                                     variable=self.onTheFly, anchor='w')
        chbOnTheFly.grid(row=0, column=3, sticky='we')
        wckToolTips.register(chbOnTheFly, 
                             ("문자열을 암호화/복호화\n" + 
                              "< ctrl-e >    암호화\n" + 
                              "< ctrl-d >    복호화"))        
        #Frame Encoding
        ###############
        frEncoding = tk.Frame(self, bg=bs.theme.lightest, relief=tk.RAISED,bd=3)
        frEncoding.grid(row=3, padx=10, pady=5, sticky='we')
        frEncoding.grid_columnconfigure(0, weight=1)
        ####
        labEncodingTitle = tk.Label(frEncoding, text='Encoding', font="bold", 
                                    bg=bs.theme.darkest, fg='white')
        labEncodingTitle.grid(row=0, sticky='we', columnspan=2)
        txt = 'base64 문자열로 인코딩/디코딩                        persent 문자열로 인코딩/디코딩'

        labEncodingInfo = tk.Label(frEncoding, text=txt, anchor='w', 
                                   bg=bs.theme.lightest, fg=bs.theme.dark)
        labEncodingInfo.grid(row=1, columnspan=2, pady=3)
        
        frEncDecButt = tk.Frame(frEncoding, bg=bs.theme.lightest)
        frEncDecButt.grid(row=2, padx=20, pady=5)
        b1 = tk.Button(frEncDecButt, text='인코딩', command=self.encodeFile, 
                       width=12, bg=bs.theme.light)
        b1.grid(row=0, column=0, padx=5)

        b2 = tk.Button(frEncDecButt, text='디코딩', command=self.decodeFile, 
                       width=12, bg=bs.theme.light)
        b2.grid(row=0, column=1, padx=5)

        b3 = tk.Button(frEncDecButt, text='인코딩', command=self.encodeFile2, 
                       width=12, bg=bs.theme.light)
        b3.grid(row=0, column=2, padx=5)
        
        b4 = tk.Button(frEncDecButt, text='디코딩', command=self.decodeFile2, 
                       width=12, bg=bs.theme.light)
        b4.grid(row=0, column=3, padx=5)


        
        # Frame encryption
        ##################
        frEncryption = tk.Frame(self,bg=bs.theme.lightest,relief=tk.RAISED,bd=3)
        frEncryption.grid(row=2, padx=10, pady=10, sticky='we')
        frEncryption.grid_columnconfigure(0, weight=1)
        ####
        labEncryptionTitle = tk.Label(frEncryption, 
                                      text='암호화', bg=bs.theme.darkest,
                                      fg='white',font="bold")
        labEncryptionTitle.grid(sticky='we')
        txt = 'Advanced Encryption Standard (AES)방식으로 암호화/복호화'
        labEncryInfo = tk.Label(frEncryption, text=txt, anchor='w', 
                                bg=bs.theme.lightest, fg=bs.theme.dark)
        labEncryInfo.grid(pady=3)
        #     frame password
        frPassword = tk.Frame(frEncryption, bg=bs.theme.lightest)
        frPassword.grid(sticky='w')
        #
        self.lock_image = tk.PhotoImage(data=bs.theme.gifKey)
        labLockIcon = tk.Label(frPassword, image=self.lock_image)
        labPwd = tk.Label(frPassword, text='비밀번호:', width=12, 
                          bg=bs.theme.lightest)
        self.entPwd = tk.Entry(frPassword, width=32, show='*')
        labLockIcon.grid(row=1, column=0, padx=5)
        labPwd.grid(row=1, column=1)
        self.entPwd.grid(row=1, column=2)
        
        # Frame pwd keyfile
        frPwdFile = tk.Frame(frEncryption, bg=bs.theme.lightest)
        frPwdFile.grid(sticky='w')
        #
        chbPwdNote = tk.Checkbutton(frPwdFile, bg=bs.theme.lightest,
                                    highlightthickness=0,
                                    text='키파일 사용',
                                    variable=self.useKeyFile, anchor='w')
        self.imgPwdFile = tk.PhotoImage(data=bs.theme.gifKeyFile)
        labPwdFileIcon = tk.Label(frPwdFile, image=self.imgPwdFile, 
                                  bg=bs.theme.light)
        labPwdFile = tk.Label(frPwdFile, text='키파일:', width=12, 
                              bg=bs.theme.lightest)
        self.entPwdFile = tk.Entry(frPwdFile, width=46)
        butPwdFile = tk.Button(frPwdFile, text='불러오기', bg=bs.theme.light, 
                               command=self.openPwdKeyFileDialog, width=8)
        chbPwdNote.grid(row=0, column=2,sticky='w')
        labPwdFileIcon.grid(row=1, column=0, padx=5)
        labPwdFile.grid(row=1, column=1)
        self.entPwdFile.grid(row=1, column=2)
        butPwdFile.grid(row=1, column=3, padx=5)
        
        # Frame string/binary selection
        frStrBin = tk.Frame(frEncryption, bg=bs.theme.lightest)
        frStrBin.grid()
        self.typeStrBin = tk.StringVar()
        self.typeStrBin.set('binary')
        rbTypeBin = tk.Radiobutton(frStrBin, text="실행파일", value='binary', 
                                   variable=self.typeStrBin, bg=bs.theme.light, 
                                   width=12)
        wckToolTips.register(rbTypeBin, 'Output file in binary form')
        rbTypeStr = tk.Radiobutton(frStrBin, text="문자파일 (utf-8)", 
                                   variable=self.typeStrBin,
                                   value='utf-8', width=12, bg=bs.theme.light)
        wckToolTips.register(rbTypeStr, 'Output file in text form')
        rbTypeBin.grid(row=0, column=0, pady=20, padx=5)
        rbTypeStr.grid(row=0, column=1, pady=20, padx=5)
        
        # Frame encryption buttons
        ##########################
        frButtEncrypt = tk.Frame(frEncryption, bg=bs.theme.lightest)
        frButtEncrypt.grid(row=5, pady=5)
        self.bEncr = tk.Button(frButtEncrypt, text='암호화',
                               width=12, bg=bs.theme.light)
        self.bEncr.grid(row=1, column=0, padx=5)
        self.bDecr = tk.Button(frButtEncrypt, text='복호화', width=12,
                               bg=bs.theme.light)
        self.bDecr.grid(row=1, column=1, padx=5)
        bView = tk.Button(frButtEncrypt, text='결과보기', width=12, 
                          bg=bs.theme.light, command=(lambda arg='on_the_fly': 
                                                      self.decryptFile(arg)))
        bView.grid(row=1, column=2, padx=5)
        bViewTip = ('입력파일을 열어봅니다.')
        wckToolTips.register(bView, bViewTip)
        bEdit = tk.Button(frButtEncrypt, text='편집', bg=bs.theme.light,
                          width=12,command=(lambda arg='on_the_fly_edit': 
                                            self.decryptFile(arg)))
        bEdit.grid(row=1, column=3, padx=5)
        bEditTip = ('입력파일을 편집합니다.')
        wckToolTips.register(bEdit, bEditTip)
            
        #Frame quit
        ###########
        frQuit = tk.Frame(self, bg=bs.theme.normal)
        frQuit.grid(row=6, sticky='we', padx=20)
        self.imgQuit = tk.PhotoImage(data=bs.theme.gifQuit)
        self.b3 = tk.Button(frQuit, text='종료',command=root.quit, width=80, 
                            compound='left', image=self.imgQuit, 
                            bg=bs.theme.light)
        self.b3.grid(row=1, column=0, padx=5, pady=10)
        self.imgAbout = tk.PhotoImage(data=bs.theme.gifAbout)
        b6 = tk.Button(frQuit, text='BitShade란?', bg=bs.theme.light, width=80,
                       command=(lambda : self.callbackButtAbout()),
                       compound='left', image=self.imgAbout)
        b6.grid(row=1, column=1, pady=10)
        
#------------------------------------------------------------------------------
if __name__ == '__main__':
    root = tk.Tk()
    root.title("BitShade " + vers)
    root.resizable(0,0)
    app = App(root)
    root.bind('<Control-w>',(lambda arg: root.quit()))
    app.mainloop()
