from antiphish.model import train, save_model

if __name__ == "__main__":
    pipe = train()
    save_model(pipe, "models/model.joblib")
    print("Model trained and saved to models/model.joblib")
