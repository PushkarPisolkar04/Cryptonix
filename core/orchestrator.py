"""
Main orchestrator that coordinates all assessment stages
"""

import asyncio
from datetime import datetime
from typing import List, Optional
from pathlib import Path

from loguru import logger

from core.config import Config
from core.models import AssessmentScope, AssessmentResult, StageResult
from core.state_manager import StateManager
from stages import (
    OSINTStage,
    DiscoveryStage,
    VulnerabilityStage,
    ThreatModelingStage,
    ExploitMappingStage,
    ExploitationStage,
    PostExploitationStage,
    LateralMovementStage,
    ImpactDemonstrationStage,
    ReportingStage
)


class PenTestOrchestrator:
    """Orchestrates the entire penetration testing pipeline"""
    
    STAGE_MAP = {
        'osint': OSINTStage,
        'discovery': DiscoveryStage,
        'vulnerability': VulnerabilityStage,
        'vuln_scan': VulnerabilityStage,  # Alias
        'threat_modeling': ThreatModelingStage,
        'threat_model': ThreatModelingStage,  # Alias
        'exploit_mapping': ExploitMappingStage,
        'exploit_map': ExploitMappingStage,  # Alias
        'exploitation': ExploitationStage,
        'post_exploitation': PostExploitationStage,
        'post_exploit': PostExploitationStage,  # Alias
        'lateral_movement': LateralMovementStage,
        'lateral': LateralMovementStage,  # Alias
        'impact': ImpactDemonstrationStage,
        'impact_demo': ImpactDemonstrationStage,  # Alias
        'reporting': ReportingStage
    }
    
    def __init__(self, config: Config, output_dir: str):
        self.config = config
        self.output_dir = Path(output_dir)
        self.state_manager = StateManager(self.output_dir / 'state.db')
        
    async def run_assessment(
        self,
        scope: AssessmentScope,
        selected_stages: Optional[List[str]] = None
    ) -> AssessmentResult:
        """Run the complete assessment pipeline"""
        
        start_time = datetime.now()
        logger.info("="*60)
        logger.info("🚀 Starting Automated Penetration Test")
        logger.info("="*60)
        
        # Determine which stages to run
        stages_to_run = selected_stages or list(self.STAGE_MAP.keys())
        
        # Initialize result
        result = AssessmentResult(
            target=scope.target,
            start_time=start_time,
            scope=scope
        )
        
        # Run each stage sequentially (with state passing)
        stage_data = {}
        
        for stage_name in stages_to_run:
            if stage_name not in self.STAGE_MAP:
                logger.warning(f"Unknown stage: {stage_name}, skipping")
                continue
            
            try:
                # Check if we can resume from checkpoint
                checkpoint = self.state_manager.load_checkpoint(stage_name)
                if checkpoint:
                    logger.info(f"Resuming {stage_name} from checkpoint")
                    stage_data[stage_name] = checkpoint
                    continue
                
                # Initialize and run stage
                stage_class = self.STAGE_MAP[stage_name]
                stage = stage_class(self.config, scope, stage_data)
                
                logger.info(f"\n{'='*60}")
                logger.info(f"📍 Stage: {stage.name}")
                logger.info(f"{'='*60}")
                
                stage_result = await stage.execute()
                
                # Store result
                stage_data[stage_name] = stage_result
                result.add_stage_result(stage_name, stage_result)
                
                # Save checkpoint
                self.state_manager.save_checkpoint(stage_name, stage_result)
                
                logger.success(f"✅ {stage.name} completed")
                
            except Exception as e:
                logger.error(f"❌ Stage {stage_name} failed: {e}")
                result.add_error(stage_name, str(e))
                
                # Decide whether to continue or abort
                if stage_name in ['osint', 'discovery']:
                    # Critical stages - abort
                    logger.critical("Critical stage failed, aborting assessment")
                    break
                else:
                    # Non-critical - continue
                    logger.warning(f"Continuing despite {stage_name} failure")
        
        # Finalize result
        result.end_time = datetime.now()
        result.duration = (result.end_time - start_time).total_seconds()
        
        # Generate final report
        reporting_stage = ReportingStage(self.config, scope, stage_data)
        report_path = await reporting_stage.generate_final_report(result)
        result.report_path = str(report_path)
        
        logger.info("\n" + "="*60)
        logger.success("🎉 Assessment Complete!")
        logger.info("="*60)
        
        return result
