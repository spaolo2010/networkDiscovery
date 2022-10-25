import threading
from sharedobject import test
import time
from sharedobject import test

class A (threading.Thread):
    def __init__(self, test,lock):
        #self.lock = threading.Lock()
        self.test = test
        #self.name = name
        self.lock = lock
        threading.Thread.__init__(self)


    def  run(self) -> None:
        self.lock.acquire()
        for i in range(10):
            time.sleep(1)
            self.test.setValue(i)
            print(self.name ,self.test.getValue() + 4)
            i+=1
        self.lock.release()





def main():
    pass
    a =[]
    ts = test()
    lock = threading.Lock()
    for i in range (2):
        t = A(ts,lock)
        t.start()

if __name__ == '__main__':
    main()