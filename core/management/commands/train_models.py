import os
import sys
from django.core.management.base import BaseCommand, CommandError
from django.conf import settings
from django.utils import timezone
import logging
from typing import Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("ml_training.log"),
    ],
)

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = "Train machine learning models for network intrusion detection"

    def add_arguments(self, parser):
        """Add command line arguments"""

        # Required arguments
        parser.add_argument(
            "dataset_path", type=str, help="Path to the CIC-IDS2017 dataset CSV file"
        )

        # Optional arguments
        parser.add_argument(
            "--model-type",
            type=str,
            choices=["binary", "multiclass", "anomaly", "all"],
            default="all",
            help="Type of model to train (default: all)",
        )

        parser.add_argument(
            "--test-size",
            type=float,
            default=0.2,
            help="Proportion of dataset to use for testing (default: 0.2)",
        )

        parser.add_argument(
            "--contamination",
            type=float,
            default=0.1,
            help="Contamination parameter for anomaly detection (default: 0.1)",
        )

        parser.add_argument(
            "--random-state",
            type=int,
            default=42,
            help="Random state for reproducibility (default: 42)",
        )

        parser.add_argument(
            "--output-dir",
            type=str,
            default=None,
            help="Directory to save trained models (default: MEDIA_ROOT/ml_models)",
        )

        parser.add_argument(
            "--plot-features",
            action="store_true",
            help="Generate feature importance plots",
        )

        parser.add_argument(
            "--top-features",
            type=int,
            default=20,
            help="Number of top features to show in plots (default: 20)",
        )

        parser.add_argument(
            "--skip-preprocessing",
            action="store_true",
            help="Skip data preprocessing if data is already clean",
        )

        parser.add_argument(
            "--verbose", action="store_true", help="Enable verbose output"
        )

    def handle(self, *args, **options):
        """Main command handler"""

        # Set logging level based on verbosity
        if options["verbose"]:
            logging.getLogger().setLevel(logging.DEBUG)

        try:
            # Import the trainer (assuming it's in your ml_models app)
            from core.intrusion_trainer import NetworkIntrusionTrainer

        except ImportError as e:
            raise CommandError(f"Could not import NetworkIntrusionTrainer: {e}")

        # Validate dataset path
        dataset_path = options["dataset_path"]
        if not os.path.exists(dataset_path):
            raise CommandError(f"Dataset file not found: {dataset_path}")

        # Validate test size
        test_size = options["test_size"]
        if not 0 < test_size < 1:
            raise CommandError("Test size must be between 0 and 1")

        # Validate contamination
        contamination = options["contamination"]
        if not 0 < contamination < 1:
            raise CommandError("Contamination must be between 0 and 1")

        # Set output directory
        output_dir = options["output_dir"]
        if output_dir and not os.path.exists(output_dir):
            try:
                os.makedirs(output_dir, exist_ok=True)
            except OSError as e:
                raise CommandError(
                    f"Could not create output directory {output_dir}: {e}"
                )

        self.stdout.write(
            self.style.SUCCESS(
                f"Starting ML model training with dataset: {dataset_path}"
            )
        )

        # Initialize trainer
        trainer = NetworkIntrusionTrainer(data_path=dataset_path)

        # Override output directory if specified
        if output_dir:
            trainer.models_dir = output_dir
            os.makedirs(output_dir, exist_ok=True)

        try:
            # Load and preprocess data
            self.stdout.write("Loading dataset...")
            df = trainer.load_data(dataset_path)

            if not options["skip_preprocessing"]:
                self.stdout.write("Preprocessing data...")
                X, y = trainer.preprocess_data(df)
            else:
                self.stdout.write("Skipping preprocessing...")
                X = df.drop(columns=[trainer.label_column])
                y = df[trainer.label_column]

            self.stdout.write(
                self.style.SUCCESS(
                    f"Data loaded: {X.shape[0]} samples, {X.shape[1]} features"
                )
            )

            # Train models based on selection
            model_type = options["model_type"]
            results = {}

            if model_type in ["binary", "all"]:
                self.stdout.write("Training binary classifier...")
                try:
                    binary_results = trainer.train_binary_classifier(
                        X, y, test_size, options["random_state"]
                    )
                    results["binary"] = binary_results
                    self.stdout.write(
                        self.style.SUCCESS(
                            f"Binary classifier - Accuracy: {binary_results['accuracy']:.4f}, "
                            f"F1: {binary_results['f1_score']:.4f}"
                        )
                    )
                except Exception as e:
                    self.stdout.write(
                        self.style.ERROR(f"Binary classifier training failed: {e}")
                    )

            if model_type in ["multiclass", "all"]:
                self.stdout.write("Training multi-class classifier...")
                try:
                    multiclass_results = trainer.train_multiclass_classifier(
                        X, y, test_size, options["random_state"]
                    )
                    results["multiclass"] = multiclass_results
                    self.stdout.write(
                        self.style.SUCCESS(
                            f"Multi-class classifier - Accuracy: {multiclass_results['accuracy']:.4f}, "
                            f"F1: {multiclass_results['f1_score']:.4f}"
                        )
                    )
                except Exception as e:
                    self.stdout.write(
                        self.style.ERROR(f"Multi-class classifier training failed: {e}")
                    )

            if model_type in ["anomaly", "all"]:
                self.stdout.write("Training anomaly detector...")
                try:
                    anomaly_results = trainer.train_anomaly_detector(
                        X, contamination, options["random_state"]
                    )
                    results["anomaly"] = anomaly_results
                    self.stdout.write(
                        self.style.SUCCESS(
                            f"Anomaly detector - Outliers detected: {anomaly_results['n_outliers']}"
                        )
                    )
                except Exception as e:
                    self.stdout.write(
                        self.style.ERROR(f"Anomaly detector training failed: {e}")
                    )

            # Save models
            if results:
                self.stdout.write("Saving trained models...")
                saved_models = trainer.save_models()

                # Generate evaluation report
                evaluation_report = trainer.generate_evaluation_report()

                # Display summary
                self.display_training_summary(results, saved_models)

                # Generate feature importance plots if requested
                if options["plot_features"]:
                    self.stdout.write("Generating feature importance plots...")
                    top_features = options["top_features"]

                    for model_name in results.keys():
                        if model_name in ["binary", "multiclass"]:
                            try:
                                trainer.plot_feature_importance(
                                    model_name, top_features
                                )
                                self.stdout.write(
                                    self.style.SUCCESS(
                                        f"Feature importance plot saved for {model_name} model"
                                    )
                                )
                            except Exception as e:
                                self.stdout.write(
                                    self.style.WARNING(
                                        f"Could not generate plot for {model_name}: {e}"
                                    )
                                )

                self.stdout.write(
                    self.style.SUCCESS(
                        f"\nTraining completed successfully! "
                        f"Models saved to: {trainer.models_dir}"
                    )
                )
            else:
                self.stdout.write(
                    self.style.ERROR("No models were trained successfully")
                )

        except Exception as e:
            logger.exception("Training failed with exception")
            raise CommandError(f"Training failed: {e}")

    def display_training_summary(self, results: dict, saved_models: dict):
        """Display a formatted summary of training results"""

        self.stdout.write("\n" + "=" * 60)
        self.stdout.write(self.style.SUCCESS("TRAINING RESULTS SUMMARY"))
        self.stdout.write("=" * 60)

        for model_type, model_results in results.items():
            self.stdout.write(f"\n{model_type.upper()} MODEL:")
            self.stdout.write("-" * 30)

            if "accuracy" in model_results:
                self.stdout.write(f"Accuracy:  {model_results['accuracy']:.4f}")
            if "precision" in model_results:
                self.stdout.write(f"Precision: {model_results['precision']:.4f}")
            if "recall" in model_results:
                self.stdout.write(f"Recall:    {model_results['recall']:.4f}")
            if "f1_score" in model_results:
                self.stdout.write(f"F1-Score:  {model_results['f1_score']:.4f}")
            if "auc_score" in model_results:
                self.stdout.write(f"AUC Score: {model_results['auc_score']:.4f}")

            if model_type in saved_models:
                self.stdout.write(f"Saved to:  {saved_models[model_type]['path']}")
                self.stdout.write(f"Model ID:  {saved_models[model_type]['model_id']}")

        self.stdout.write("\n" + "=" * 60)

        # Display file locations
        self.stdout.write("\nSAVED FILES:")
        self.stdout.write("-" * 20)
        for model_type, info in saved_models.items():
            self.stdout.write(f"{model_type.title()}: {info['path']}")

        self.stdout.write(f"\nTraining completed at: {timezone.now()}")

    def validate_dataset(self, dataset_path: str) -> bool:
        """Validate that the dataset file is readable and has expected format"""

        try:
            import pandas as pd

            # Try to read first few rows
            df_sample = pd.read_csv(dataset_path, nrows=5)

            if df_sample.empty:
                raise CommandError("Dataset appears to be empty")

            if df_sample.shape[1] < 10:
                self.stdout.write(
                    self.style.WARNING(
                        f"Dataset has only {df_sample.shape[1]} columns. "
                        f"Expected more for CIC-IDS2017 format."
                    )
                )

            return True

        except Exception as e:
            raise CommandError(f"Could not validate dataset: {e}")


# Additional utility command for model management
class ModelManagementCommand(BaseCommand):
    """Utility command for managing trained models"""

    help = "Manage trained ML models"

    def add_arguments(self, parser):
        parser.add_argument(
            "action",
            choices=["list", "activate", "deactivate", "delete", "evaluate"],
            help="Action to perform",
        )

        parser.add_argument(
            "--model-id",
            type=int,
            help="Model ID for activate/deactivate/delete/evaluate actions",
        )

        parser.add_argument(
            "--model-type",
            type=str,
            choices=["binary", "multiclass", "anomaly"],
            help="Filter by model type for list action",
        )

    def handle(self, *args, **options):
        try:
            from core.models import MLModel
        except ImportError:
            raise CommandError(
                "Could not import MLModel. Check your model configuration."
            )

        action = options["action"]

        if action == "list":
            self.list_models(options.get("model_type"))
        elif action in ["activate", "deactivate", "delete"]:
            model_id = options.get("model_id")
            if not model_id:
                raise CommandError(f"--model-id is required for {action} action")
            self.manage_model(action, model_id)
        elif action == "evaluate":
            model_id = options.get("model_id")
            if not model_id:
                raise CommandError("--model-id is required for evaluate action")
            self.evaluate_model(model_id)

    def list_models(self, model_type: Optional[str] = None):
        """List all trained models"""
        try:
            from core.models import MLModel

            queryset = MLModel.objects.all()
            if model_type:
                queryset = queryset.filter(model_type=model_type)

            models = queryset.order_by("-created_at")

            if not models:
                self.stdout.write("No trained models found.")
                return

            self.stdout.write("\nTRAINED MODELS:")
            self.stdout.write("=" * 80)

            for model in models:
                status = "ACTIVE" if model.is_active else "INACTIVE"
                self.stdout.write(
                    f"ID: {model.id} | {model.name} | Type: {model.model_type} | "
                    f"Accuracy: {model.accuracy:.4f} | Status: {status}"
                )
                self.stdout.write(f"  Created: {model.created_at}")
                self.stdout.write(f"  Path: {model.file_path}")
                self.stdout.write("-" * 80)

        except Exception as e:
            raise CommandError(f"Could not list models: {e}")

    def manage_model(self, action: str, model_id: int):
        """Activate, deactivate, or delete a model"""
        try:
            from core.models import MLModel

            model = MLModel.objects.get(id=model_id)

            if action == "activate":
                # Deactivate other models of the same type
                MLModel.objects.filter(model_type=model.model_type).update(
                    is_active=False
                )
                model.is_active = True
                model.save()
                self.stdout.write(
                    self.style.SUCCESS(f"Model {model_id} activated successfully")
                )

            elif action == "deactivate":
                model.is_active = False
                model.save()
                self.stdout.write(
                    self.style.SUCCESS(f"Model {model_id} deactivated successfully")
                )

            elif action == "delete":
                # Delete model file if it exists
                if os.path.exists(model.file_path):
                    os.remove(model.file_path)

                model.delete()
                self.stdout.write(
                    self.style.SUCCESS(f"Model {model_id} deleted successfully")
                )

        except Exception as e:
            raise CommandError(f"Could not {action} model {model_id}: {e}")

    def evaluate_model(self, model_id: int):
        """Evaluate a specific model"""
        try:
            from core.models import MLModel
            from ml_models.network_intrusion_trainer import load_trained_model

            model = MLModel.objects.get(id=model_id)

            # Load the model
            model_package = load_trained_model(model.file_path)
            if not model_package:
                raise CommandError(f"Could not load model from {model.file_path}")

            # Display model information
            self.stdout.write(f"\nMODEL EVALUATION - ID: {model_id}")
            self.stdout.write("=" * 50)
            self.stdout.write(f"Name: {model.name}")
            self.stdout.write(f"Type: {model.model_type}")
            self.stdout.write(f"Created: {model.created_at}")
            self.stdout.write(f"Accuracy: {model.accuracy:.4f}")
            self.stdout.write(f"Precision: {model.precision:.4f}")
            self.stdout.write(f"Recall: {model.recall:.4f}")
            self.stdout.write(f"F1-Score: {model.f1_score:.4f}")
            self.stdout.write(f"Active: {'Yes' if model.is_active else 'No'}")

            # Display feature count
            feature_count = len(model_package.get("feature_columns", []))
            self.stdout.write(f"Features: {feature_count}")

            # Display evaluation metrics if available
            eval_metrics = model_package.get("evaluation_metrics", {})
            if eval_metrics:
                self.stdout.write("\nDETAILED METRICS:")
                self.stdout.write("-" * 30)
                for key, value in eval_metrics.items():
                    if isinstance(value, (int, float)):
                        self.stdout.write(f"{key}: {value}")

        except Exception as e:
            raise CommandError(f"Could not evaluate model {model_id}: {e}")
