import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score

def train_netdefender():
    print("[*] Loading NetDefender dataset (3,413 packets)...")
    df = pd.read_csv('netdefender_training_data.csv')

    # --- FEATURE ENGINEERING ---
    # Pro-Tip: Drop IPs and Timestamps so the AI generalizes to NEW attacks.
    # We must also convert the text protocols into numbers for the AI.
    protocol_map = {'TCP': 6, 'UDP': 17, 'ICMP': 1, 'UNKNOWN': 0}
    df['protocol'] = df['protocol'].map(protocol_map)

    # Define our Features (X) and our Target/Label (y)
    X = df[['protocol', 'packet_length']]
    y = df['is_attack']

    # --- TRAIN/TEST SPLIT ---
    # Give the AI 80% of the data to learn, and hide 20% to test it like a final exam
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # --- AI TRAINING ---
    print("[*] Training the Random Forest AI...")
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)

    # --- AI TESTING ---
    print("[*] Testing the AI against unseen data...")
    predictions = model.predict(X_test)

    # Calculate and print the results
    acc = accuracy_score(y_test, predictions)
    print("\n" + "="*40)
    print(f"[+] AI Training Complete!")
    print(f"[+] NetDefender Accuracy: {acc * 100:.2f}%")
    print("="*40)
    
    print("\nDetailed Performance Report:")
    print(classification_report(y_test, predictions, target_names=['Normal (0)', 'Attack (1)']))

    # --- SAVE THE BRAIN ---
    import joblib
    joblib.dump(model, 'netdefender_ai_model.pkl')
    print("[+] Model saved as 'netdefender_ai_model.pkl' for live deployment!")

if __name__ == "__main__":
    train_netdefender()
