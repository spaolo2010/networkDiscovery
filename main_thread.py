import threading
from sharedobject import test
import time
lock = threading.Lock()
def a(obj):
    pass
    i=0
    lock.acquire()
    for _ in range(10):
        time.sleep(1)
        obj.setValue(i)
        print (obj.getValue() + 4)
        i+=1
    lock.release()


def b(obj):
    lock.acquire()
    i=100
    for _ in range(10):
        time.sleep(1)
        obj.setValue(i)
        print(obj.getValue() + 20)
        i += 1
    lock.release()


def main():
    pass
    a =[]
    ts = test()
    #t_1 = threading.Thread(name='t_1', target=a ,  args={ts,})
    #t_1.start()
    #t_2 = threading.Thread(name='t_2', target=b, args={ts,})
    #t_2.start()
    ts.setValue(10)
    a.append(ts)
    del ts
    try:
       print(a[0].getValue())
       print (ts.getValue())
    except UnboundLocalError:
      print ("error")
    finally:
        print ("END")

if __name__ == '__main__':
    main()