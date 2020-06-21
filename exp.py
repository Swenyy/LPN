#!/usr/bin/python3
# -*- coding: utf-8 -*-
from builtins import len

import random
import math
from binascii import b2a_hex, a2b_hex, hexlify, unhexlify
import FHE
import pandas as pd
import tkinter as tk
import tkinter
from tkinter import messagebox
from tkinter import simpledialog
from tkinter import filedialog
from tkinter import ttk

#生成随机字符串
def generate_random_str(randomlength=16):
    '''Generate random str'''
    random_str = ''
    base_str = 'ABCDEFGHIGKLMNOPQRSTUVWXYZabcdefghigklmnopqrstuvwxyz0123456789!@#$%^&*-_+='
    length = len(base_str) - 1
    for i in range(randomlength):
        random_str += base_str[random.randint(0, length)]
    return random_str

#生成随机列表数据
def generate_data(N=10):
    '''Generate random list data'''
    name = []
    for i in range(N):
        name.append(generate_random_str(10))

    grade = []

    for i in range(N):
        grade.append(random.randrange(1, 100))

    return (name, grade)

#给定字符串返回整数
def s_to_int(s):
    '''给定字符串返回整数'''
    b = s.encode('utf-8')
    h = hexlify(b)
    return int(h.decode('utf-8'), 16)

#整数->字符串
def int_to_s(x):
    s = str(hex(x))
    s = s[2:len(s)]
    b = s.encode('utf-8')
    t = unhexlify(b)
    res = t.decode('utf-8')
    return res

def str_to_int(message, d=0):
    if not isinstance(message, str):
        raise TypeError('Expected int type plaintext but got: %s' % type(message))

    length = len(message)
    if length == 0:
        return []

    a = []
    if d > 0:
        q = length // d
        for i in range(0, q):
            a.append(s_to_int(message[i * d: (i + 1) * d]))
        if length % d > 0:
            a.append(s_to_int(message[q * d: length]))
    else:
        a.append(s_to_int(message))
    return a

def is_same_encrypt(x, y, q):
    if (x - y) % q == 0:
        return True
    else:
        return False

def search_data(filepath, q, enc1=None, enc2=None):
    df = pd.read_csv(filepath, encoding='utf-8')
    column_headers = list(df.columns.values)
    e_data1 = list(df[column_headers[0]])
    e_data2 = list(df[column_headers[1]])
    data1 = []
    data2 = []

    if not isinstance(q, int):
        q = int(q)
    if enc1 and enc2 == None:
        tmp = q
        if not isinstance(enc1, int):
            tmp = int(enc1)
        else:
            tmp = enc1
        for i in range(len(e_data1)):
            x = int(e_data1[i])
            if is_same_encrypt(x, tmp, q):
                data1.append(e_data1[i])
                data2.append(e_data2[i])

    elif enc1 == None and enc2:
        tmp = q
        if not isinstance(enc2, int):
            tmp = int(enc2)
        else:
            tmp = enc2
        for i in range(len(e_data2)):
            x = int(e_data2[i])
            if is_same_encrypt(x, tmp, q) == True:
                data1.append(e_data1[i])
                data2.append(e_data2[i])

    elif enc1 and enc2:
        tmp1 = q
        tmp2 = q
        if not isinstance(enc1, int):
            tmp1 = int(enc1)
        else:
            tmp1 = enc1
        if not isinstance(enc2, int):
            tmp2 = int(enc2)
        else:
            tmp2 = enc2
        for i in range(len(e_data1)):
            x = int(e_data1[i])
            y = int(e_data2[i])
            if is_same_encrypt(x, tmp1, q) and is_same_encrypt(x, tmp2, q):
                data1.append(e_data1[i])
                data2.append(e_data2[i])

    return (column_headers, data1, data2)

def add_data(filepath, q, enc1, enc2):
    df = pd.read_csv(filepath, encoding='utf-8')
    column_headers = list(df.columns.values)
    e_data1 = list(df[column_headers[0]])
    e_data2 = list(df[column_headers[1]])
    if not isinstance(q, int):
        q = int(q)
    if not isinstance(enc1, int):
        enc1 = int(enc1)
    if not isinstance(enc2, int):
        enc2 = int(enc2)
    length = len(e_data1)
    for i in range(length):
        x = int(e_data1[i])
        if is_same_encrypt(x, enc1, q):
            y = int(e_data2[i])
            y = y + enc2
            e_data2[i] = str(y)

    return (column_headers, e_data1, e_data2)


def center_window(window, w, h):
    '''
    窗口居中函数
    '''
    ws = window.winfo_screenwidth()
    hs = window.winfo_screenheight()
    x = (ws / 2) - (w / 2)
    y = (hs / 2) - (h / 2)
    window.geometry('%dx%d+%d+%d' % (w, h, x, y))


def main_interface():
    '''
    主界面
    '''
    interface = tk.Tk()
    interface.title('同态加密测试')
    center_window(interface, 500, 300)

    tk.Button(interface, text='数据生成', font=('宋体', 14), command=generate_random_data).place(x=200, y=50)
    tk.Button(interface, text='密钥生成', font=('宋体', 14), command=generate_key).place(x=80, y=100)
    tk.Button(interface, text='数据加密', font=('宋体', 14), command=data_encrypt).place(x=80, y=200)
    tk.Button(interface, text='数据解密', font=('宋体', 14), command=data_decrypt).place(x=300, y=100)
    tk.Button(interface, text='数据查询', font=('宋体', 14), command=operate_data_opt).place(x=300, y=200)

    interface.mainloop()


def generate_random_data():
    '''
    数据生成
    '''

    filename = filedialog.asksaveasfilename(
        defaultextension='.csv',
        filetypes=[('csv Files', '*.csv'), ('All Files', '*.*')],
        initialdir='./',
        initialfile='data',
        title="保存")
    if len(filename) != 0:
        (name, grade) = generate_data(10)
        df = pd.DataFrame({'name': name,
                           'grade': grade, })
        df.to_csv(filename, index=None)
    else:
        tk.messagebox.showwarning(title='Warning', message="你没有选中任何文件")


def generate_key():
    '''
    密钥生成
    '''

    fhe = FHE.generate_HEkeypair(128)

    filename = filedialog.asksaveasfilename(
        defaultextension='.txt',
        filetypes=[('txt Files', '*.txt'), ('All Files', '*.*')],
        initialdir='./',
        initialfile='HEprikey',
        title="保存")
    if len(filename) != 0:
        FHE.save_key(filename=filename, key=fhe.p)

        filename = filedialog.asksaveasfilename(
            defaultextension='.txt',
            filetypes=[('txt Files', '*.txt'), ('All Files', '*.*')],
            initialdir='./',
            initialfile='HEpubkey',
            title="保存")
        if len(filename) != 0:
            FHE.save_key(filename=filename, key=fhe.q)

        else:
            tk.messagebox.showwarning(title='Warning', message="你没有选中任何文件")
    else:
        tk.messagebox.showwarning(title='Warning', message="你没有选中任何文件")


def data_encrypt():
    '''
    数据加密
    '''

    data_encrypt_ = tk.Tk()
    data_encrypt_.title('数据加密')
    center_window(data_encrypt_, 650, 250)

    tk.Label(data_encrypt_, text='密钥p路径：', font=('宋体', 12)).place(x=30, y=50)
    tk.Label(data_encrypt_, text='密钥q路径：', font=('宋体', 12)).place(x=30, y=100)
    tk.Label(data_encrypt_, text='加密数据路径：', font=('宋体', 12)).place(x=10, y=150)

    e1 = tk.Entry(data_encrypt_, width=60)
    e1.place(x=120, y=50)
    e2 = tk.Entry(data_encrypt_, width=60)
    e2.place(x=120, y=100)
    e3 = tk.Entry(data_encrypt_, width=60)
    e3.place(x=120, y=150)

    def load_prikey():
        filename = filedialog.askopenfilename()
        if len(filename) != 0:
            e1.delete(0, 'end')
            e1.insert('end', filename)
        else:
            tk.messagebox.showwarning(title='Warning', message="你没有选中任何文件")

    def load_pubkey():
        filename = filedialog.askopenfilename()
        if len(filename) != 0:
            e2.delete(0, 'end')
            e2.insert('end', filename)
        else:
            tk.messagebox.showwarning(title='Warning', message="你没有选中任何文件")

    def load_data():
        filename = filedialog.askopenfilename()
        if len(filename) != 0:
            e3.delete(0, 'end')
            e3.insert('end', filename)
        else:
            tk.messagebox.showwarning(title='Warning', message="你没有选中任何文件")

    def data_encrypt_but():
        p = FHE.load_key(e1.get())
        q = FHE.load_key(e2.get())
        fhe = FHE.HECrypt(p, q)

        df = pd.read_csv(e3.get(), encoding='utf-8')
        name = list(df.name)
        grade = list(df.grade)

        i_name = fhe.encrypt(s_to_int('name'))
        i_grade = fhe.encrypt(s_to_int('grade'))
        e_name = []
        for item in name:
            x = s_to_int(item)
            e_name.append(fhe.encrypt(x))
        e_grade = []
        for x in grade:
            e_grade.append(fhe.encrypt(x))

        df = pd.DataFrame({
            i_name: e_name,
            i_grade: e_grade,
        })

        tk.messagebox.showinfo(title='提示', message='保存加密结果')
        filename = filedialog.asksaveasfilename(
            defaultextension='.csv',
            filetypes=[('csv Files', '*.csv'), ('All Files', '*.*')],
            initialdir='./',
            initialfile='encrypt_data',
            title="保存")
        if len(filename) != 0:
            df.to_csv(filename, encoding='utf-8', index=None)
        else:
            tk.messagebox.showwarning(title='Warning', message="你没有选中任何文件")

    tk.Button(data_encrypt_, text='浏览', font=('宋体', 12), command=load_prikey).place(x=570, y=45)
    tk.Button(data_encrypt_, text='浏览', font=('宋体', 12), command=load_pubkey).place(x=570, y=95)
    tk.Button(data_encrypt_, text='浏览', font=('宋体', 12), command=load_data).place(x=570, y=145)
    tk.Button(data_encrypt_, text='加密', font=('宋体', 12), command=data_encrypt_but).place(x=290, y=195)

    data_encrypt_.mainloop()


def data_decrypt():
    '''
    数据解密
    '''

    data_decrypt_ = tk.Tk()
    data_decrypt_.title('数据加密')
    center_window(data_decrypt_, 650, 250)

    tk.Label(data_decrypt_, text='密钥p路径：', font=('宋体', 12)).place(x=30, y=50)
    tk.Label(data_decrypt_, text='密钥q路径：', font=('宋体', 12)).place(x=30, y=100)
    tk.Label(data_decrypt_, text='解密数据路径：', font=('宋体', 12)).place(x=10, y=150)

    e1 = tk.Entry(data_decrypt_, width=60)
    e1.place(x=120, y=50)
    e2 = tk.Entry(data_decrypt_, width=60)
    e2.place(x=120, y=100)
    e3 = tk.Entry(data_decrypt_, width=60)
    e3.place(x=120, y=150)

    def load_prikey():
        filename = filedialog.askopenfilename()
        if len(filename) != 0:
            e1.delete(0, 'end')
            e1.insert('end', filename)
        else:
            tk.messagebox.showwarning(title='Warning', message="你没有选中任何文件")

    def load_pubkey():
        filename = filedialog.askopenfilename()
        if len(filename) != 0:
            e2.delete(0, 'end')
            e2.insert('end', filename)
        else:
            tk.messagebox.showwarning(title='Warning', message="你没有选中任何文件")

    def load_data():
        filename = filedialog.askopenfilename()
        if len(filename) != 0:
            e3.delete(0, 'end')
            e3.insert('end', filename)
        else:
            tk.messagebox.showwarning(title='Warning', message="你没有选中任何文件")

    def data_decrypt_but():
        p = FHE.load_key(e1.get())
        q = FHE.load_key(e2.get())
        fhe = FHE.HECrypt(p, q)
        df = pd.read_csv(e3.get(), encoding='utf-8')

        column_headers = list(df.columns.values)
        name = []
        grade = []

        for i in range(len(column_headers)):
            if i == 0:
                name = list(df[column_headers[i]])
            elif i == 1:
                grade = list(df[column_headers[i]])
            else:
                continue

        dename = []
        for item in name:
            dename.append(int_to_s(fhe.decrypt(int(item))))

        degrade = []
        for item in grade:
            degrade.append(fhe.decrypt(int(item)))

        df = pd.DataFrame({
            'name': dename,
            'grade': degrade,
        })

        tk.messagebox.showinfo(title='提示', message='保存解密结果')
        filename = filedialog.asksaveasfilename(
            defaultextension='.csv',
            filetypes=[('csv Files', '*.csv'), ('All Files', '*.*')],
            initialdir='./',
            initialfile='decrypt_data',
            title="保存")
        if len(filename) != 0:
            df.to_csv(filename, encoding='utf-8', index=0)
        else:
            tk.messagebox.showwarning(title='Warning', message="你没有选中任何文件")

    tk.Button(data_decrypt_, text='浏览', font=('宋体', 12), command=load_prikey).place(x=570, y=45)
    tk.Button(data_decrypt_, text='浏览', font=('宋体', 12), command=load_pubkey).place(x=570, y=95)
    tk.Button(data_decrypt_, text='浏览', font=('宋体', 12), command=load_data).place(x=570, y=145)
    tk.Button(data_decrypt_, text='解密', font=('宋体', 12), command=data_decrypt_but).place(x=290, y=195)

    data_decrypt_.mainloop()


def operate_data_opt():
    operate_data_window = tk.Tk()
    operate_data_window.title('数据操作窗口')
    center_window(operate_data_window, 500, 350)

    tk.Label(operate_data_window, text='密钥p文件路径：', font=('宋体', 12)).place(x=30, y=50)
    tk.Label(operate_data_window, text='密钥q文件路径：', font=('宋体', 12)).place(x=30, y=100)
    tk.Label(operate_data_window, text='密文数据路径：', font=('宋体', 12)).place(x=30, y=150)
    tk.Label(operate_data_window, text='结果保存路径：', font=('宋体', 12)).place(x=30, y=200)
    tk.Label(operate_data_window, text='姓名：', font=('宋体', 12)).place(x=30, y=250)
    tk.Label(operate_data_window, text='成绩：', font=('宋体', 12)).place(x=160, y=250)
    tk.Label(operate_data_window, text='增量：', font=('宋体', 12)).place(x=290, y=250)

    e1 = tk.Entry(operate_data_window, width=35)
    e1.place(x=150, y=50)
    e2 = tk.Entry(operate_data_window, width=35)
    e2.place(x=150, y=100)
    e3 = tk.Entry(operate_data_window, width=35)
    e3.place(x=150, y=150)
    e4 = tk.Entry(operate_data_window, width=35)
    e4.place(x=150, y=200)
    e5 = tk.Entry(operate_data_window, width=10)
    e5.place(x=75, y=250)
    e6 = tk.Entry(operate_data_window, width=10)
    e6.place(x=205, y=250)
    e7 = tk.Entry(operate_data_window, width=10)
    e7.place(x=340, y=250)

    def load_prikey():
        filename = filedialog.askopenfilename()
        if len(filename) != 0:
            e1.delete(0, 'end')
            e1.insert('end', filename)
        else:
            tk.messagebox.showwarning(title='Warning', message="你没有选中任何文件")

    def load_pubkey():
        filename = filedialog.askopenfilename()
        if len(filename) != 0:
            e2.delete(0, 'end')
            e2.insert('end', filename)
        else:
            tk.messagebox.showwarning(title='Warning', message="你没有选中任何文件")

    def load_encryptfile():
        filename = filedialog.askopenfilename()
        if len(filename) != 0:
            e3.delete(0, 'end')
            e3.insert('end', filename)
        else:
            tk.messagebox.showwarning(title='Warning', message="你没有选中任何文件")

    def load_resfile():
        filename = filedialog.asksaveasfilename(
            defaultextension='.txt',
            filetypes=[('csv Files,*.csv')],
            initialdir='',  # 对话框中默认的路径
            initialfile='return_data',  # 对话框中初始化显示的文件名
            title="另存为"  # 弹出对话框的标题
        )
        if len(filename) != 0:
            e4.delete(0, 'end')
            e4.insert('end', filename)
        else:
            tk.messagebox.showwarning(title='Warning', message="你没有选中任何文件")

    def search_():
        m1 = e5.get()
        m2 = e6.get()
        length1 = len(m1)
        length2 = len(m2)
        if length1 == 0 and length2 == 0:
            tk.messagebox.showwarning(title='Warning', message="姓名和成绩不能同时为空")
            return None

        if len(e3.get()) == 0 or len(e4.get()) == 0:
            tk.messagebox.showwarning(title='Warning', message="密文文件路径和结果文件路径不能为空")
            return None

        p = FHE.load_key(e1.get())
        q = FHE.load_key(e2.get())
        fhe = FHE.HECrypt(p, q)
        filepath = e3.get()
        resfile = e4.get()
        enc1 = None
        enc2 = None
        if length1:
            enc1 = fhe.encrypt(s_to_int(m1))
        if length2:
            enc2 = fhe.encrypt(int(m2))

        (column_headers, data1, data2) = search_data(filepath, q, enc1, enc2)
        df = pd.DataFrame({column_headers[0]: data1,
                           column_headers[1]: data2,
                           })
        df.to_csv(resfile, index=0)

    def Add_():
        m1 = e5.get()
        m2 = e7.get()
        length1 = len(m1)
        length2 = len(m2)
        if length1 == 0 and length2 == 0:
            tk.messagebox.showwarning(title='Warning', message="姓名和增量不能同时为空")
            return None

        if len(e3.get()) == 0 or len(e4.get()) == 0:
            tk.messagebox.showwarning(title='Warning', message="密文文件路径和结果文件路径不能为空")
            return None

        p = FHE.load_key(e1.get())
        q = FHE.load_key(e2.get())
        fhe = FHE.HECrypt(p, q)
        filepath = e3.get()
        resfile = e4.get()
        enc1 = None
        enc2 = None
        if length1:
            enc1 = fhe.encrypt(s_to_int(m1))
        if length2:
            enc2 = fhe.encrypt(int(m2))

        (column_headers, data1, data2) = add_data(filepath, q, enc1, enc2)
        df = pd.DataFrame({column_headers[0]: data1,
                           column_headers[1]: data2,
                           })
        df.to_csv(resfile, index=0)

    tk.Button(operate_data_window, text='浏览', font=('宋体', 12), command=load_prikey).place(x=410, y=48)
    tk.Button(operate_data_window, text='浏览', font=('宋体', 12), command=load_pubkey).place(x=410, y=96)
    tk.Button(operate_data_window, text='浏览', font=('宋体', 12), command=load_encryptfile).place(x=410, y=144)
    tk.Button(operate_data_window, text='浏览', font=('宋体', 12), command=load_resfile).place(x=410, y=194)
    tk.Button(operate_data_window, text='查询', font=('宋体', 12), command=search_).place(x=100, y=295)
    tk.Button(operate_data_window, text='修改', font=('宋体', 12), command=Add_).place(x=300, y=295)

    operate_data_window.mainloop()


if __name__ == "__main__":
    main_interface()




