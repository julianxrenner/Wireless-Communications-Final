from sklearn import tree
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import accuracy_score
import warnings

warnings.filterwarnings("ignore", category=UserWarning)


class DetectionModel:
    def __init__(self):
        # Initialize decision tree classifier
        self.clf = tree.DecisionTreeClassifier()
        self.clean_data()
        self.train()

    def detect(self, packet):
        # Predict packet label
        prediction = self.clf.predict([packet])
        return "Normal" if prediction == 0 else "Malicious"

    def clean_data(self):
        # Load dataset
        df = pd.read_csv("SSDP.csv", low_memory=False)

        # Define features
        features = [
            "frame.len",
            "frame.time_epoch",
            "ip.src",
            "ip.dst",
            "ip.proto",
            "ip.ttl",
            "tcp.srcport",
            "tcp.dstport",
            "tcp.seq",
            "tcp.ack",
            "tcp.flags.syn",
            "udp.srcport",
            "udp.dstport",
            "udp.length",
            "Label",
        ]

        # Keep only available features
        available_features = [col for col in features if col in df.columns]
        df = df[available_features]

        # Encode categorical data
        encoder = LabelEncoder()
        for col in df.columns:
            if df[col].dtype == object or col == "Label":
                df[col] = encoder.fit_transform(df[col].astype(str))

        # Save cleaned data
        df.to_csv("SSDP.csv", index=False)

    def train(self):
        # Load cleaned dataset
        data = pd.read_csv("SSDP.csv")
        data.fillna(0, inplace=True)

        # Split into features and labels
        X = data.iloc[:, :-1]
        y = data.iloc[:, -1]

        # Split into training and test sets
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.3, random_state=42
        )

        # Train decision tree classifier
        self.clf.fit(X_train, y_train)


if __name__ == "__main__":
    detection_system = DetectionModel()
    detection_system.clean_data()
    detection_system.train()
