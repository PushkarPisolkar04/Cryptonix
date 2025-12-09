"""
Base class for all assessment stages
"""

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Dict, Any

from loguru import logger

from core.config import Config
from core.models import AssessmentScope, StageResult


class BaseStage(ABC):
    """Base class for all assessment stages"""
    
    def __init__(self, config: Config, scope: AssessmentScope, previous_results: Dict[str, Any]):
        self.config = config
        self.scope = scope
        self.previous_results = previous_results
        self.start_time = None
        self.end_time = None
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Stage name"""
        pass
    
    @property
    @abstractmethod
    def description(self) -> str:
        """Stage description"""
        pass
    
    @abstractmethod
    async def run(self) -> Dict[str, Any]:
        """Execute the stage logic - must be implemented by subclasses"""
        pass
    
    async def execute(self) -> StageResult:
        """Execute the stage and return results"""
        self.start_time = datetime.now()
        logger.info(f"Starting {self.name}")
        logger.info(f"Description: {self.description}")
        
        errors = []
        warnings = []
        data = {}
        success = False
        
        try:
            # Run the stage
            data = await self.run()
            success = True
            
        except Exception as e:
            logger.exception(f"Stage {self.name} failed: {e}")
            errors.append(str(e))
            success = False
        
        finally:
            self.end_time = datetime.now()
            duration = (self.end_time - self.start_time).total_seconds()
            
            result = StageResult(
                stage_name=self.name,
                success=success,
                start_time=self.start_time,
                end_time=self.end_time,
                duration=duration,
                data=data,
                errors=errors,
                warnings=warnings
            )
            
            logger.info(f"{self.name} completed in {duration:.2f}s")
            
            return result
    
    def get_previous_stage_data(self, stage_name: str) -> Dict[str, Any]:
        """Get data from a previous stage"""
        if stage_name in self.previous_results:
            stage_result = self.previous_results[stage_name]
            if hasattr(stage_result, 'data'):
                return stage_result.data
            return stage_result
        return {}
