from sklearn import tree
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import accuracy_score
import warnings

warnings.filterwarnings("ignore", category=UserWarning)

class DetectionModel:
    def __init__(self):
        self.clf = tree.DecisionTreeClassifier()
        self.clean_data()
        self.train()

    def detect(self, packet):
        prediction = self.clf.predict([packet])
        return "Normal" if prediction == 0 else "Malicious"

    def clean_data(self):
        df = pd.read_csv("SSDP.csv", low_memory=False)

        features = [
            "frame.len", "frame.time_epoch", "ip.src", "ip.dst", "ip.proto",
            "ip.ttl", "tcp.srcport", "tcp.dstport", "tcp.seq", "tcp.ack",
            "tcp.flags.syn", "udp.srcport", "udp.dstport",
            "udp.length", "Label"
        ]

        available_features = [col for col in features if col in df.columns]
        df = df[available_features]

        encoder = LabelEncoder()
        for col in df.columns:
            if df[col].dtype == object or col == "Label":
                df[col] = encoder.fit_transform(df[col].astype(str))

        df.to_csv("SSDP.csv", index=False)

    def train(self):
        data = pd.read_csv('SSDP.csv')
        data.fillna(0, inplace=True)
        X = data.iloc[:, :-1]
        y = data.iloc[:, -1]
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)
        self.clf.fit(X_train, y_train)


if __name__ == "__main__":
    detection_system = DetectionModel()
    detection_system.clean_data()
    detection_system.train()