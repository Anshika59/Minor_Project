"""
Model Training and Benchmark Script

Trains the Phishing Email Detector ML Classification Engine,
benchmarks Logistic Regression against Random Forest,
and outputs evaluation metrics (Accuracy, Precision, Recall, F1-Score).
"""

from src.ml_engine import MLEngine


def main():
    print("=" * 60)
    print("Phishing Email Detector — Machine Learning Training Engine")
    print("=" * 60)

    engine = MLEngine()
    metrics = engine.train_and_benchmark()

    print("\nBenchmark Evaluation Results:")
    print("-" * 60)
    comparison = metrics.get("benchmark_comparison", {})
    for model_name, m in comparison.items():
        print(f"[{m.get('model', model_name)}]")
        print(f"  Accuracy:  {m.get('accuracy', 0.0):.4f}")
        print(f"  Precision: {m.get('precision', 0.0):.4f}")
        print(f"  Recall:    {m.get('recall', 0.0):.4f}")
        print(f"  F1-Score:  {m.get('f1_score', 0.0):.4f}\n")

    print(f"Selected Champion Model: {metrics.get('best_model')}")
    print(f"Champion Accuracy:  {metrics.get('accuracy', 0.0):.4f}")
    print(f"Champion F1-Score:  {metrics.get('f1_score', 0.0):.4f}")
    print("=" * 60)


if __name__ == "__main__":
    main()
