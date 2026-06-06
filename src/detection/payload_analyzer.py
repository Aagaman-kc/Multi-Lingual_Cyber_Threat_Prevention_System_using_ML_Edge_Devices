import joblib

class AppAttackDetector:
    def __init__(self, model_path, vectorizer_path, label_encoder_path):
        self.model = joblib.load(model_path)
        self.vectorizer = joblib.load(vectorizer_path)
        self.le = joblib.load(label_encoder_path)

    def detect(self, payload):
        X = self.vectorizer.transform([payload])
        pred_id = self.model.predict(X)[0]
        proba = self.model.predict_proba(X)[0].max()
        label = self.le.inverse_transform([pred_id])[0]
        return {'label': label, 'confidence': proba, 'module': 'app_attack'}