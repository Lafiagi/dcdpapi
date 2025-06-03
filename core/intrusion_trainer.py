import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import train_test_split, cross_val_score, GridSearchCV
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    accuracy_score,
    precision_recall_fscore_support,
    roc_auc_score,
    roc_curve,
)
from sklearn.utils.class_weight import compute_class_weight
import joblib
import logging
import os
import json
from datetime import datetime
from typing import Dict, List, Tuple, Any, Optional
import matplotlib.pyplot as plt
import warnings

warnings.filterwarnings("ignore")

from django.conf import settings
from core.models import MLModel

logger = logging.getLogger(__name__)


class NetworkIntrusionTrainer:
    """
    ML model trainer for network intrusion detection using CIC-IDS2017 dataset
    Supports binary classification (benign/malicious) and multi-class attack type classification
    """

    def __init__(self, data_path: str = None):
        self.data_path = data_path
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        self.feature_columns = []
        self.models = {}
        self.evaluation_results = {}

        # CIC-IDS2017 feature mapping to match your analyzer output
        self.feature_mapping = self._get_feature_mapping()

        # Create models directory if it doesn't exist
        self.models_dir = os.path.join(settings.MEDIA_ROOT, "ml_models")
        os.makedirs(self.models_dir, exist_ok=True)

    def _get_feature_mapping(self) -> Dict[str, str]:
        """Map CIC-IDS2017 dataset columns to your analyzer feature names"""
        return {
            # Flow duration and basic features
            "Flow Duration": "flow_duration",
            "Total Fwd Packets": "total_fwd_packets",
            "Total Backward Packets": "total_backward_packets",
            "Total Length of Fwd Packets": "total_length_fwd_packets",
            "Total Length of Bwd Packets": "total_length_bwd_packets",
            # Forward packet statistics
            "Fwd Packet Length Max": "fwd_packet_length_max",
            "Fwd Packet Length Min": "fwd_packet_length_min",
            "Fwd Packet Length Mean": "fwd_packet_length_mean",
            "Fwd Packet Length Std": "fwd_packet_length_std",
            # Backward packet statistics
            "Bwd Packet Length Max": "bwd_packet_length_max",
            "Bwd Packet Length Min": "bwd_packet_length_min",
            "Bwd Packet Length Mean": "bwd_packet_length_mean",
            "Bwd Packet Length Std": "bwd_packet_length_std",
            # Inter-arrival time features
            "Flow IAT Mean": "flow_iat_mean",
            "Flow IAT Std": "flow_iat_std",
            "Flow IAT Max": "flow_iat_max",
            "Flow IAT Min": "flow_iat_min",
            "Fwd IAT Mean": "fwd_iat_mean",
            "Fwd IAT Std": "fwd_iat_std",
            "Fwd IAT Max": "fwd_iat_max",
            "Fwd IAT Min": "fwd_iat_min",
            "Bwd IAT Mean": "bwd_iat_mean",
            "Bwd IAT Std": "bwd_iat_std",
            "Bwd IAT Max": "bwd_iat_max",
            "Bwd IAT Min": "bwd_iat_min",
            # TCP flags
            "FIN Flag Count": "fin_flag_count",
            "SYN Flag Count": "syn_flag_count",
            "RST Flag Count": "rst_flag_count",
            "PSH Flag Count": "psh_flag_count",
            "ACK Flag Count": "ack_flag_count",
            "URG Flag Count": "urg_flag_count",
            "CWE Flag Count": "cwe_flag_count",
            "ECE Flag Count": "ece_flag_count",
            # Additional features
            "Down/Up Ratio": "down_up_ratio",
            "Average Packet Size": "average_packet_size",
            "Avg Fwd Segment Size": "avg_fwd_segment_size",
            "Avg Bwd Segment Size": "avg_bwd_segment_size",
            "Fwd Header Length": "fwd_header_length",
            "Bwd Header Length": "bwd_header_length",
            "Fwd Packets/s": "fwd_packets_per_second",
            "Bwd Packets/s": "bwd_packets_per_second",
            "Min Packet Length": "min_packet_length",
            "Max Packet Length": "max_packet_length",
            "Packet Length Mean": "packet_length_mean",
            "Packet Length Std": "packet_length_std",
            "Packet Length Variance": "packet_length_variance",
            # Subflow features
            "Subflow Fwd Packets": "subflow_fwd_packets",
            "Subflow Fwd Bytes": "subflow_fwd_bytes",
            "Subflow Bwd Packets": "subflow_bwd_packets",
            "Subflow Bwd Bytes": "subflow_bwd_bytes",
            # Window and segment features
            "Init_Win_bytes_forward": "init_win_bytes_forward",
            "Init_Win_bytes_backward": "init_win_bytes_backward",
            "act_data_pkt_fwd": "act_data_pkt_fwd",
            "min_seg_size_forward": "min_seg_size_forward",
            # Active/Idle time features
            "Active Mean": "active_mean",
            "Active Std": "active_std",
            "Active Max": "active_max",
            "Active Min": "active_min",
            "Idle Mean": "idle_mean",
            "Idle Std": "idle_std",
            "Idle Max": "idle_max",
            "Idle Min": "idle_min",
        }

    def load_data(self, file_path: str = None) -> pd.DataFrame:
        """Load and preprocess the CIC-IDS2017 dataset"""
        if file_path is None:
            file_path = self.data_path

        if not file_path or not os.path.exists(file_path):
            raise FileNotFoundError(f"Dataset file not found: {file_path}")

        logger.info(f"Loading dataset from {file_path}")

        # Try different encodings and separators
        encodings = ["utf-8", "latin-1", "iso-8859-1"]
        separators = [",", ";", "\t"]

        df = None
        for encoding in encodings:
            for sep in separators:
                try:
                    df = pd.read_csv(
                        file_path, encoding=encoding, sep=sep, low_memory=False
                    )
                    if df.shape[1] > 1:  # Valid DataFrame
                        logger.info(
                            f"Successfully loaded with encoding={encoding}, separator='{sep}'"
                        )
                        break
                except Exception as e:
                    continue
            if df is not None and df.shape[1] > 1:
                break

        if df is None or df.shape[1] <= 1:
            raise ValueError(
                "Could not load the dataset with any encoding/separator combination"
            )

        logger.info(f"Dataset loaded: {df.shape[0]} rows, {df.shape[1]} columns")

        # Clean column names (remove extra spaces)
        df.columns = df.columns.str.strip()

        # Display basic info about the dataset
        logger.info(f"Columns: {list(df.columns)}")

        # Identify label column (usually 'Label' or similar)
        label_columns = [
            col
            for col in df.columns
            if "label" in col.lower() or "class" in col.lower()
        ]
        if not label_columns:
            # Try to find by position (usually last column)
            label_columns = [df.columns[-1]]

        self.label_column = label_columns[0]
        logger.info(f"Using '{self.label_column}' as label column")

        # Display label distribution
        label_dist = df[self.label_column].value_counts()
        logger.info(f"Label distribution:\n{label_dist}")

        return df

    def preprocess_data(self, df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.Series]:
        """Preprocess the dataset for training"""
        logger.info("Starting data preprocessing...")

        # Separate features and labels
        X = df.drop(columns=[self.label_column])
        y = df[self.label_column]

        # Handle infinite values
        X = X.replace([np.inf, -np.inf], np.nan)

        # Handle missing values
        missing_percent = (X.isnull().sum() / len(X)) * 100
        high_missing_cols = missing_percent[missing_percent > 50].index.tolist()

        if high_missing_cols:
            logger.warning(
                f"Dropping columns with >50% missing values: {high_missing_cols}"
            )
            X = X.drop(columns=high_missing_cols)

        # Fill remaining missing values
        numeric_cols = X.select_dtypes(include=[np.number]).columns
        X[numeric_cols] = X[numeric_cols].fillna(X[numeric_cols].median())

        # Handle categorical columns if any
        categorical_cols = X.select_dtypes(include=["object"]).columns
        for col in categorical_cols:
            X[col] = X[col].fillna(
                X[col].mode()[0] if not X[col].mode().empty else "unknown"
            )

        # Remove duplicate rows
        initial_rows = len(X)
        combined_df = pd.concat([X, y], axis=1)
        combined_df = combined_df.drop_duplicates()
        X = combined_df.drop(columns=[self.label_column])
        y = combined_df[self.label_column]

        logger.info(f"Removed {initial_rows - len(X)} duplicate rows")

        # Store feature columns for later use
        self.feature_columns = X.columns.tolist()

        # Clean labels (remove extra spaces, normalize case)
        y = y.astype(str).str.strip().str.upper()

        logger.info(f"Preprocessed data shape: {X.shape}")
        logger.info(f"Final label distribution:\n{y.value_counts()}")

        return X, y

    def prepare_binary_labels(self, y: pd.Series) -> pd.Series:
        """Convert multi-class labels to binary (benign vs malicious)"""
        binary_labels = y.copy()
        benign_labels = ["BENIGN", "NORMAL"]

        # Convert to binary: 0 for benign, 1 for malicious
        binary_labels = binary_labels.apply(lambda x: 0 if x in benign_labels else 1)

        logger.info(f"Binary label distribution:\n{binary_labels.value_counts()}")
        return binary_labels

    def train_binary_classifier(
        self,
        X: pd.DataFrame,
        y: pd.Series,
        test_size: float = 0.2,
        random_state: int = 42,
    ) -> Dict:
        """Train binary classifier (benign vs malicious)"""
        logger.info("Training binary classifier...")

        # Prepare binary labels
        y_binary = self.prepare_binary_labels(y)

        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X,
            y_binary,
            test_size=test_size,
            random_state=random_state,
            stratify=y_binary,
        )

        # Scale features
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)

        # Handle class imbalance
        class_weights = compute_class_weight(
            "balanced", classes=np.unique(y_train), y=y_train
        )
        class_weight_dict = {i: class_weights[i] for i in range(len(class_weights))}

        # Train Random Forest with hyperparameter tuning
        param_grid = {
            "n_estimators": [100, 200],
            "max_depth": [10, 20, None],
            "min_samples_split": [2, 5],
            "min_samples_leaf": [1, 2],
        }

        rf = RandomForestClassifier(
            random_state=random_state, class_weight=class_weight_dict, n_jobs=-1
        )

        # Grid search with cross-validation
        grid_search = GridSearchCV(
            rf, param_grid, cv=3, scoring="f1", n_jobs=-1, verbose=1
        )
        grid_search.fit(X_train_scaled, y_train)

        best_model = grid_search.best_estimator_

        # Predictions
        y_pred = best_model.predict(X_test_scaled)
        y_pred_proba = best_model.predict_proba(X_test_scaled)

        # Evaluation metrics
        accuracy = accuracy_score(y_test, y_pred)
        precision, recall, f1, _ = precision_recall_fscore_support(
            y_test, y_pred, average="weighted"
        )
        auc_score = roc_auc_score(y_test, y_pred_proba[:, 1])

        results = {
            "model": best_model,
            "scaler": self.scaler,
            "accuracy": accuracy,
            "precision": precision,
            "recall": recall,
            "f1_score": f1,
            "auc_score": auc_score,
            "best_params": grid_search.best_params_,
            "classification_report": classification_report(y_test, y_pred),
            "confusion_matrix": confusion_matrix(y_test, y_pred).tolist(),
            "feature_importance": dict(
                zip(self.feature_columns, best_model.feature_importances_)
            ),
        }

        self.models["binary"] = results
        self.evaluation_results["binary"] = results

        logger.info(
            f"Binary classifier trained - Accuracy: {accuracy:.4f}, F1: {f1:.4f}, AUC: {auc_score:.4f}"
        )

        return results

    def train_multiclass_classifier(
        self,
        X: pd.DataFrame,
        y: pd.Series,
        test_size: float = 0.2,
        random_state: int = 42,
    ) -> Dict:
        """Train multi-class classifier for attack type detection"""
        logger.info("Training multi-class classifier...")

        # Filter out very rare classes (less than 50 samples)
        class_counts = y.value_counts()
        rare_classes = class_counts[class_counts < 50].index

        if len(rare_classes) > 0:
            logger.warning(f"Filtering out rare classes: {rare_classes.tolist()}")
            mask = ~y.isin(rare_classes)
            X = X[mask]
            y = y[mask]

        # Encode labels
        y_encoded = self.label_encoder.fit_transform(y)

        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X,
            y_encoded,
            test_size=test_size,
            random_state=random_state,
            stratify=y_encoded,
        )

        # Use the same scaler as binary classifier or create new one
        if hasattr(self.scaler, "mean_"):
            X_train_scaled = self.scaler.transform(X_train)
            X_test_scaled = self.scaler.transform(X_test)
        else:
            scaler = StandardScaler()
            X_train_scaled = scaler.fit_transform(X_train)
            X_test_scaled = scaler.transform(X_test)

        # Handle class imbalance
        class_weights = compute_class_weight(
            "balanced", classes=np.unique(y_train), y=y_train
        )
        class_weight_dict = {i: class_weights[i] for i in range(len(class_weights))}

        # Train Random Forest
        rf = RandomForestClassifier(
            n_estimators=200,
            max_depth=20,
            min_samples_split=2,
            min_samples_leaf=1,
            random_state=random_state,
            class_weight=class_weight_dict,
            n_jobs=-1,
        )

        rf.fit(X_train_scaled, y_train)

        # Predictions
        y_pred = rf.predict(X_test_scaled)
        y_pred_proba = rf.predict_proba(X_test_scaled)

        # Evaluation metrics
        accuracy = accuracy_score(y_test, y_pred)
        precision, recall, f1, _ = precision_recall_fscore_support(
            y_test, y_pred, average="weighted"
        )

        # Get class names
        class_names = self.label_encoder.classes_

        results = {
            "model": rf,
            "label_encoder": self.label_encoder,
            "accuracy": accuracy,
            "precision": precision,
            "recall": recall,
            "f1_score": f1,
            "classification_report": classification_report(
                y_test, y_pred, target_names=class_names
            ),
            "confusion_matrix": confusion_matrix(y_test, y_pred).tolist(),
            "class_names": class_names.tolist(),
            "feature_importance": dict(
                zip(self.feature_columns, rf.feature_importances_)
            ),
        }

        self.models["multiclass"] = results
        self.evaluation_results["multiclass"] = results

        logger.info(
            f"Multi-class classifier trained - Accuracy: {accuracy:.4f}, F1: {f1:.4f}"
        )

        return results

    def train_anomaly_detector(
        self, X: pd.DataFrame, contamination: float = 0.1, random_state: int = 42
    ) -> Dict:
        """Train anomaly detection model using Isolation Forest"""
        logger.info("Training anomaly detector...")

        # Use only benign samples for training (unsupervised)
        # In real scenario, you might want to use only normal traffic
        X_scaled = (
            self.scaler.fit_transform(X)
            if not hasattr(self.scaler, "mean_")
            else self.scaler.transform(X)
        )

        # Train Isolation Forest
        iso_forest = IsolationForest(
            contamination=contamination, random_state=random_state, n_jobs=-1
        )

        iso_forest.fit(X_scaled)

        # Get anomaly scores
        anomaly_scores = iso_forest.decision_function(X_scaled)
        predictions = iso_forest.predict(X_scaled)

        results = {
            "model": iso_forest,
            "contamination": contamination,
            "anomaly_scores": anomaly_scores,
            "predictions": predictions,
            "n_outliers": len(predictions[predictions == -1]),
        }

        self.models["anomaly"] = results
        self.evaluation_results["anomaly"] = results

        logger.info(
            f"Anomaly detector trained - Outliers detected: {results['n_outliers']}"
        )

        return results

    def save_models(self) -> Dict[str, str]:
        """Save trained models to disk and register in Django"""
        saved_models = {}

        for model_type, model_data in self.models.items():
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            model_filename = f"{model_type}_model_{timestamp}.joblib"
            model_path = os.path.join(self.models_dir, model_filename)

            # Prepare model package
            model_package = {
                "model": model_data["model"],
                "scaler": self.scaler if model_type != "anomaly" else None,
                "label_encoder": model_data.get("label_encoder"),
                "feature_columns": self.feature_columns,
                "evaluation_metrics": {
                    k: v
                    for k, v in model_data.items()
                    if k not in ["model", "scaler", "label_encoder"]
                },
            }

            # Save model
            joblib.dump(model_package, model_path)

            # Register in Django
            ml_model = MLModel.objects.create(
                name=f"{model_type.title()} Classifier - {timestamp}",
                model_type=model_type,
                file_path=model_path,
                accuracy=model_data.get("accuracy", 0),
                precision=model_data.get("precision", 0),
                recall=model_data.get("recall", 0),
                f1_score=model_data.get("f1_score", 0),
                training_data_size=len(self.feature_columns),
                feature_count=len(self.feature_columns),
                hyperparameters=model_data.get("best_params", {}),
                evaluation_metrics=model_data.get("classification_report", ""),
                is_active=True,
            )

            saved_models[model_type] = {
                "path": model_path,
                "model_id": ml_model.id,
                "accuracy": model_data.get("accuracy", 0),
            }

            logger.info(f"Saved {model_type} model to {model_path}")

        return saved_models

    def generate_evaluation_report(self) -> Dict:
        """Generate comprehensive evaluation report"""
        report = {
            "training_timestamp": datetime.now().isoformat(),
            "models_trained": list(self.models.keys()),
            "feature_count": len(self.feature_columns),
            "evaluation_results": {},
        }

        for model_type, results in self.evaluation_results.items():
            model_report = {
                "accuracy": results.get("accuracy", 0),
                "precision": results.get("precision", 0),
                "recall": results.get("recall", 0),
                "f1_score": results.get("f1_score", 0),
                "feature_importance": results.get("feature_importance", {}),
            }

            if model_type == "binary":
                model_report["auc_score"] = results.get("auc_score", 0)
                model_report["confusion_matrix"] = results.get("confusion_matrix", [])
            elif model_type == "multiclass":
                model_report["class_names"] = results.get("class_names", [])
                model_report["confusion_matrix"] = results.get("confusion_matrix", [])
            elif model_type == "anomaly":
                model_report["contamination"] = results.get("contamination", 0)
                model_report["n_outliers"] = results.get("n_outliers", 0)

            report["evaluation_results"][model_type] = model_report

        # Save report
        report_path = os.path.join(
            self.models_dir,
            f"evaluation_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
        )
        with open(report_path, "w") as f:
            json.dump(report, f, indent=2)

        logger.info(f"Evaluation report saved to {report_path}")

        return report

    def plot_feature_importance(self, model_type: str = "binary", top_n: int = 20):
        """Plot feature importance for a trained model"""
        if model_type not in self.models:
            logger.error(f"Model {model_type} not found")
            return

        feature_importance = self.models[model_type].get("feature_importance", {})
        if not feature_importance:
            logger.error(f"Feature importance not available for {model_type} model")
            return

        # Sort features by importance
        sorted_features = sorted(
            feature_importance.items(), key=lambda x: x[1], reverse=True
        )[:top_n]
        features, importance = zip(*sorted_features)

        plt.figure(figsize=(12, 8))
        plt.barh(range(len(features)), importance)
        plt.yticks(range(len(features)), features)
        plt.xlabel("Feature Importance")
        plt.title(f"Top {top_n} Feature Importance - {model_type.title()} Model")
        plt.gca().invert_yaxis()
        plt.tight_layout()

        plot_path = os.path.join(
            self.models_dir, f"{model_type}_feature_importance.png"
        )
        plt.savefig(plot_path, dpi=300, bbox_inches="tight")
        plt.show()

        logger.info(f"Feature importance plot saved to {plot_path}")

    def train_all_models(
        self, data_path: str, test_size: float = 0.2, contamination: float = 0.1
    ) -> Dict:
        """Train all models in sequence"""
        logger.info("Starting comprehensive model training...")

        # Load and preprocess data
        df = self.load_data(data_path)
        X, y = self.preprocess_data(df)

        results = {}

        # Train binary classifier
        try:
            binary_results = self.train_binary_classifier(X, y, test_size)
            results["binary"] = binary_results
        except Exception as e:
            logger.error(f"Binary classifier training failed: {e}")

        # Train multi-class classifier
        try:
            multiclass_results = self.train_multiclass_classifier(X, y, test_size)
            results["multiclass"] = multiclass_results
        except Exception as e:
            logger.error(f"Multi-class classifier training failed: {e}")

        # Train anomaly detector
        try:
            anomaly_results = self.train_anomaly_detector(X, contamination)
            results["anomaly"] = anomaly_results
        except Exception as e:
            logger.error(f"Anomaly detector training failed: {e}")

        # Save models
        saved_models = self.save_models()
        results["saved_models"] = saved_models

        # Generate evaluation report
        evaluation_report = self.generate_evaluation_report()
        results["evaluation_report"] = evaluation_report

        logger.info("Model training completed successfully!")

        return results


# Utility functions for model management
def load_trained_model(model_path: str) -> Dict:
    """Load a trained model from disk"""
    try:
        model_package = joblib.load(model_path)
        logger.info(f"Model loaded from {model_path}")
        return model_package
    except Exception as e:
        logger.error(f"Failed to load model from {model_path}: {e}")
        return None


def evaluate_model_performance(
    model_package: Dict, X_test: pd.DataFrame, y_test: pd.Series
) -> Dict:
    """Evaluate a loaded model on test data"""
    try:
        model = model_package["model"]
        scaler = model_package.get("scaler")

        # Prepare test data
        if scaler:
            X_test_scaled = scaler.transform(X_test)
        else:
            X_test_scaled = X_test

        # Make predictions
        predictions = model.predict(X_test_scaled)

        # Calculate metrics
        accuracy = accuracy_score(y_test, predictions)
        precision, recall, f1, _ = precision_recall_fscore_support(
            y_test, predictions, average="weighted"
        )

        return {
            "accuracy": accuracy,
            "precision": precision,
            "recall": recall,
            "f1_score": f1,
            "predictions": predictions,
        }
    except Exception as e:
        logger.error(f"Model evaluation failed: {e}")
        return None


# Example usage script
if __name__ == "__main__":
    # Example training script
    trainer = NetworkIntrusionTrainer()

    # Replace with your dataset path
    dataset_path = "/path/to/your/cicids2017_dataset.csv"

    # Train all models
    results = trainer.train_all_models(
        data_path=dataset_path, test_size=0.2, contamination=0.1
    )

    # Print results summary
    print("\n=== Training Results Summary ===")
    for model_type, model_results in results.items():
        if model_type not in ["saved_models", "evaluation_report"]:
            print(f"\n{model_type.title()} Model:")
            print(f"  Accuracy: {model_results.get('accuracy', 0):.4f}")
            print(f"  Precision: {model_results.get('precision', 0):.4f}")
            print(f"  Recall: {model_results.get('recall', 0):.4f}")
            print(f"  F1-Score: {model_results.get('f1_score', 0):.4f}")

    # Generate feature importance plots
    trainer.plot_feature_importance("binary")
    trainer.plot_feature_importance("multiclass")
