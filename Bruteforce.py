import threading
import time

class bruteforceCheck():
    def __init__(self, max):
        self.attempts = 0
        self.timestamp = []
        self.passAttempt = False
        self.success = False
        self.timeVar = 0
        self.max = max
        self.nextA = 0
        self.total = 0
        self.blocked = False

    def timer(self):
        self.nextA = self.timestamp[0]
        while True:
            time.sleep(1)
            self.timeVar += 1
            if self.success:
                break
            else:
                if self.nextA + 60 == self.timeVar:
                    self.timestamp.pop(0)
                    self.attempts -= 1
                    if self.attempts == 0:
                        self.timeVar = 0
                        break
                    else:
                        self.nextA = self.timestamp[0]

    def initTimer(self):
        t = threading.Thread(name='initTimer', target=self.timer,
                             daemon=True)
        t.start()

    def enum(self):
        if self.attempts < self.max:
            self.total += 1
            if self.max == 5:
                if self.total > 10:
                    self.blocked = True
                    return
            else:
                if self.total > 5:
                    self.blocked = True
                    return
            self.passAttempt = True
            self.attempts += 1
            self.timestamp.append(self.timeVar)
        else:
            self.passAttempt = False

    def match(self):
        self.success = True
