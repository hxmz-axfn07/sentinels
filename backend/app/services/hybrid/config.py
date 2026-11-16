from pydantic import BaseModel, ConfigDict, Field, model_validator


class HybridScoringConfig(BaseModel):
    """Versioned, bounded weights for the explainable hybrid priority score."""

    model_config = ConfigDict(frozen=True)

    version: str = "hybrid-v1"
    rule_low_weight: int = Field(default=10, ge=0, le=100)
    rule_medium_weight: int = Field(default=25, ge=0, le=100)
    rule_high_weight: int = Field(default=45, ge=0, le=100)
    rule_critical_weight: int = Field(default=65, ge=0, le=100)
    ml_base_weight: int = Field(default=20, ge=0, le=100)
    ml_rank_weight: int = Field(default=30, ge=0, le=100)
    exact_flow_bonus: int = Field(default=15, ge=0, le=100)
    severity_informational_max: int = Field(default=0, ge=0, le=99)
    severity_low_max: int = Field(default=24, ge=1, le=99)
    severity_medium_max: int = Field(default=49, ge=1, le=99)
    severity_high_max: int = Field(default=74, ge=1, le=99)

    @model_validator(mode="after")
    def validate_score_bands(self) -> "HybridScoringConfig":
        bands = (
            self.severity_informational_max,
            self.severity_low_max,
            self.severity_medium_max,
            self.severity_high_max,
            100,
        )
        if bands != tuple(sorted(set(bands))):
            raise ValueError("hybrid severity bands must be strictly increasing")
        if self.ml_base_weight + self.ml_rank_weight > 100:
            raise ValueError("maximum ML contribution cannot exceed 100")
        if not self.version.strip() or len(self.version) > 32:
            raise ValueError("hybrid scoring version must contain 1 to 32 characters")
        return self

    def rule_weight(self, severity: str) -> int:
        return {
            "low": self.rule_low_weight,
            "medium": self.rule_medium_weight,
            "high": self.rule_high_weight,
            "critical": self.rule_critical_weight,
        }[severity]

    def classify(self, score: float) -> str:
        if score <= self.severity_informational_max:
            return "informational"
        if score <= self.severity_low_max:
            return "low"
        if score <= self.severity_medium_max:
            return "medium"
        if score <= self.severity_high_max:
            return "high"
        return "critical"
