from sklearn import tree
import pandas as pd
from sklearn.model_selection import train_test_split

class DetectionSystem:
    def __init__(self):
        self.clf = tree.DecisionTreeClassifier()
        score = self.train()


    def detect(self, packet):
      prediction = self.clf.predict([packet])[0]
      return "Normal" if prediction == 0 else "Malicious"
    
    def train(self):
        data = pd.read_csv('Encoded_SSDP_Dataset.csv')
        X = data.iloc[:, :-1]
        y = data.iloc[:, -1]
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)
        self.clf.fit(X_train, y_train)
        