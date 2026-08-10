import pickle

MODEL_PATH = r"D:\Semester5\NLP\CyberLens\static\model\threat_category\threat_category_model.pkl"

with open(MODEL_PATH, "rb") as f:
    model_package = pickle.load(f)

print(type(model_package))

if isinstance(model_package, dict):
    print("\nMODEL PACKAGE KEYS:")
    for key, value in model_package.items():
        print(
            key,
            "->",
            type(value)
        )
else:
    print("Model is not a dictionary.")