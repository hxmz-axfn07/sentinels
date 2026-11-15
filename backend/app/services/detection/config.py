from pydantic import BaseModel, ConfigDict, Field, model_validator


class SeverityThresholds(BaseModel):
    model_config = ConfigDict(frozen=True)

    low: int = Field(ge=1, le=1_000_000)
    medium: int = Field(ge=1, le=1_000_000)
    high: int = Field(ge=1, le=1_000_000)
    critical: int = Field(ge=1, le=1_000_000)

    @model_validator(mode="after")
    def require_increasing_thresholds(self) -> "SeverityThresholds":
        values = (self.low, self.medium, self.high, self.critical)
        if values != tuple(sorted(set(values))):
            raise ValueError("severity thresholds must be strictly increasing")
        return self


class DetectionConfig(BaseModel):
    model_config = ConfigDict(frozen=True)

    @model_validator(mode="before")
    @classmethod
    def merge_partial_environment_values(cls, values):
        if not isinstance(values, dict):
            return values
        merged = cls.model_construct().model_dump()
        for name, value in values.items():
            if isinstance(merged.get(name), dict) and isinstance(value, dict):
                merged[name].update(value)
            else:
                merged[name] = value
        return merged

    port_scan_enabled: bool = True
    port_scan_thresholds: SeverityThresholds = Field(
        default_factory=lambda: SeverityThresholds(low=5, medium=10, high=25, critical=50)
    )
    syn_flood_enabled: bool = True
    syn_flood_thresholds: SeverityThresholds = Field(
        default_factory=lambda: SeverityThresholds(low=20, medium=100, high=500, critical=1_000)
    )
    connection_attempts_enabled: bool = True
    connection_attempts_thresholds: SeverityThresholds = Field(
        default_factory=lambda: SeverityThresholds(low=10, medium=25, high=50, critical=100)
    )

    @model_validator(mode="after")
    def validate_port_scan_range(self) -> "DetectionConfig":
        if self.port_scan_thresholds.critical > 65_535:
            raise ValueError("port-scan thresholds cannot exceed the TCP/UDP port range")
        return self
