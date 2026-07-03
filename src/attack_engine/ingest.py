import pandas as pd
from pathlib import Path


def load_attack_vectors(path: str):
    df = pd.read_csv(path)
    required_columns = {"id", "category", "adversarial_prompt", "expected_behavior", "version"}
    if not required_columns.issubset(df.columns):
        missing = required_columns - set(df.columns)
        raise ValueError(f"Missing required columns in attack dataset: {missing}")
    return df


def save_processed_vectors(df, output_path: str):
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    df.to_parquet(output, index=False)
    print(f"Saved processed attack vectors to {output}")


if __name__ == "__main__":
    source_path = "data/raw/attack_vectors.csv"
    output_path = "data/processed/attack_vectors.parquet"
    df = load_attack_vectors(source_path)
    save_processed_vectors(df, output_path)
