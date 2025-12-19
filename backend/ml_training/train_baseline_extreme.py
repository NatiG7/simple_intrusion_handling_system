"""
Overnight baseline training for maximum coverage.
Captures traffic over 8+ hours including various usage patterns.
Creates the most comprehensive baseline possible.
"""

import os
import sys
import time
import pickle
from datetime import datetime, timedelta

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from backend.detection.FlowML import FlowMLModel
from backend.capture.PacketCapture import PacketCapture
from backend.capture.TrafficAnalysis import TrafficAnalysis
from scapy.all import get_if_list, IFACES

# OVERNIGHT Configuration
TARGET_PACKETS = 100000     # 100k packets for ultimate baseline
CAPTURE_DURATION = 28800    # 8 hours
CONTAMINATION = 0.005       # Ultra-strict - 0.5% outliers
MODEL_PATH = "models/baseline_model_overnight.pkl"
CHECKPOINT_DIR = "checkpoints"
CHECKPOINT_INTERVAL = 600   # Checkpoint every 10 minutes
MEMORY_LIMIT = 50000        # Process in batches to avoid memory issues

def select_interface():
    """Select the best active network interface"""
    available_interfaces = get_if_list()
    
    print("Available interfaces:")
    for name in available_interfaces:
        if name in IFACES:
            iface = IFACES[name]
            print(f"  {iface.description}")
            print(f"    IP: {iface.ip}\n")
    
    for name in available_interfaces:
        if name in IFACES:
            iface = IFACES[name]
            desc = iface.description.lower()
            
            if 'loopback' in desc or 'wan miniport' in desc:
                continue
            
            if iface.ip and iface.ip != '0.0.0.0' and iface.ip != '':
                print(f"Selected: {iface.description} ({iface.ip})\n")
                return name
    
    return None

def print_overnight_instructions():
    """Print overnight training instructions"""
    print("\n" + "="*70)
    print("OVERNIGHT BASELINE TRAINING - 8 HOUR SESSION")
    print("="*70)
    print("This creates the most comprehensive baseline by capturing")
    print("your complete network behavior over an extended period.")
    print()
    print("SETUP RECOMMENDATIONS:")
    print()
    print("BEFORE BED:")
    print("  - Start this script")
    print("  - Leave computer on (disable sleep mode)")
    print("  - Keep network connected")
    print("  - Optional: Run background downloads, updates")
    print("  - Optional: Leave music/podcast streaming")
    print()
    print("DURING CAPTURE:")
    print("  - Background system updates (Windows, apps)")
    print("  - Scheduled backups")
    print("  - Cloud sync (OneDrive, Dropbox, etc.)")
    print("  - Email sync")
    print("  - Any automated tasks")
    print()
    print("IN THE MORNING:")
    print("  - Script may still be running - let it finish")
    print("  - Or press Ctrl+C if you need to stop early")
    print("  - Minimum 10,000 packets recommended")
    print()
    print("CAPTURES:")
    print(f"  - Target: {TARGET_PACKETS:,} packets")
    print(f"  - Duration: {CAPTURE_DURATION//3600} hours maximum")
    print(f"  - Checkpoints: Every {CHECKPOINT_INTERVAL//60} minutes")
    print(f"  - Model size: ~10-20 MB (not affected by packet count)")
    print()
    print("DISABLE SLEEP MODE:")
    print("  Windows: Settings > System > Power > Never")
    print("  Or run: powercfg /change standby-timeout-ac 0")
    print()
    print("="*70 + "\n")

def estimate_final_size():
    """Estimate final model size"""
    print("Estimated disk usage:")
    print(f"  Final model (.pkl): ~10-20 MB")
    print(f"  Checkpoints (temp): ~50-100 MB total")
    print(f"  Logs: ~1 MB")
    print(f"  Total: ~60-120 MB")
    print()

def save_checkpoint(packets, checkpoint_num, checkpoint_dir):
    """Save packet checkpoint with compression"""
    os.makedirs(checkpoint_dir, exist_ok=True)
    
    checkpoint_file = f"{checkpoint_dir}/checkpoint_{checkpoint_num:04d}.pkl"
    
    with open(checkpoint_file, 'wb') as f:
        pickle.dump(packets, f, protocol=pickle.HIGHEST_PROTOCOL)
    
    size_mb = os.path.getsize(checkpoint_file) / (1024 * 1024)
    return checkpoint_file, size_mb

def load_all_checkpoints(checkpoint_dir):
    """Load all checkpoint files"""
    if not os.path.exists(checkpoint_dir):
        return []
    
    checkpoint_files = sorted([f for f in os.listdir(checkpoint_dir) 
                              if f.startswith('checkpoint_') and f.endswith('.pkl')])
    
    all_packets = []
    for cf in checkpoint_files:
        with open(os.path.join(checkpoint_dir, cf), 'rb') as f:
            packets = pickle.load(f)
            all_packets.extend(packets)
    
    return all_packets

def capture_overnight_baseline(interface, target_packets, duration, checkpoint_dir):
    """Capture overnight baseline with robust checkpointing"""
    sniffer = PacketCapture()
    
    start_time = time.time()
    end_time = start_time + duration
    
    print(f"Starting overnight capture...")
    print(f"Target: {target_packets:,} packets or {duration//3600} hours")
    print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Est. end: {(datetime.now() + timedelta(seconds=duration)).strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    print("The script will run in the background.")
    print("Check back in the morning or press Ctrl+C to stop early.\n")
    
    log_file = "training_log.txt"
    
    def log_message(msg):
        """Log to file and console"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_line = f"[{timestamp}] {msg}"
        print(log_line)
        with open(log_file, 'a') as f:
            f.write(log_line + '\n')
    
    try:
        sniffer.start_capture(interface, timeout=duration)
        
        last_checkpoint = start_time
        checkpoint_num = 0
        update_interval = 60  # Update every minute
        next_update = start_time + update_interval
        
        log_message("Capture started")
        
        while time.time() < end_time:
            time.sleep(10)
            current_time = time.time()
            current_count = sniffer.packet_queue.qsize()
            
            # Progress update every minute
            if current_time >= next_update:
                elapsed = int(current_time - start_time)
                remaining = int(end_time - current_time)
                packets_per_sec = current_count / elapsed if elapsed > 0 else 0
                progress = (current_count / target_packets) * 100
                
                hours_elapsed = elapsed // 3600
                mins_elapsed = (elapsed % 3600) // 60
                hours_remaining = remaining // 3600
                mins_remaining = (remaining % 3600) // 60
                
                msg = (f"Progress: {current_count:,}/{target_packets:,} ({progress:.1f}%) | "
                       f"Rate: {packets_per_sec:.1f}/s | "
                       f"Elapsed: {hours_elapsed}h {mins_elapsed}m | "
                       f"Remaining: {hours_remaining}h {mins_remaining}m")
                log_message(msg)
                
                next_update = current_time + update_interval
            
            # Checkpoint regularly
            if current_time - last_checkpoint >= CHECKPOINT_INTERVAL:
                packets = list(sniffer.packet_queue.queue)
                
                # Only checkpoint if we have new data
                if len(packets) > 0:
                    checkpoint_file, size_mb = save_checkpoint(packets, checkpoint_num, checkpoint_dir)
                    log_message(f"Checkpoint {checkpoint_num}: {len(packets):,} packets saved "
                              f"({size_mb:.2f} MB) -> {checkpoint_file}")
                    
                    # Clear queue to manage memory
                    while not sniffer.packet_queue.empty():
                        sniffer.packet_queue.get()
                    
                    checkpoint_num += 1
                
                last_checkpoint = current_time
            
            # Stop if target reached
            if current_count >= target_packets:
                log_message(f"Target of {target_packets:,} packets reached!")
                break
        
        sniffer.stop_capture_event()
        
        # Save final checkpoint
        packets = list(sniffer.packet_queue.queue)
        if len(packets) > 0:
            checkpoint_file, size_mb = save_checkpoint(packets, checkpoint_num, checkpoint_dir)
            log_message(f"Final checkpoint: {len(packets):,} packets ({size_mb:.2f} MB)")
        
        # Load all checkpoints
        log_message("Loading all checkpoints...")
        all_packets = load_all_checkpoints(checkpoint_dir)
        
        elapsed = time.time() - start_time
        hours = int(elapsed // 3600)
        mins = int((elapsed % 3600) // 60)
        
        log_message(f"Capture complete!")
        log_message(f"Duration: {hours}h {mins}m")
        log_message(f"Total packets: {len(all_packets):,}")
        log_message(f"Average rate: {len(all_packets)/elapsed:.1f} packets/sec")
        
        return all_packets
        
    except KeyboardInterrupt:
        print("\n\nCapture interrupted by user")
        sniffer.stop_capture_event()
        
        # Save what we have
        packets = list(sniffer.packet_queue.queue)
        if len(packets) > 0:
            checkpoint_file, size_mb = save_checkpoint(packets, checkpoint_num, checkpoint_dir)
            log_message(f"Interrupt checkpoint: {len(packets):,} packets ({size_mb:.2f} MB)")
        
        # Load all checkpoints
        all_packets = load_all_checkpoints(checkpoint_dir)
        elapsed = time.time() - start_time
        
        log_message(f"Captured {len(all_packets):,} packets before interruption")
        log_message(f"Duration: {elapsed//3600:.0f}h {(elapsed%3600)//60:.0f}m")
        
        if len(all_packets) < 10000:
            print(f"\nWARNING: Only {len(all_packets):,} packets captured")
            print("Recommended minimum: 10,000 packets")
            response = input("Continue with this data? (y/n): ")
            if response.lower() != 'y':
                sys.exit(1)
        
        return all_packets
    
    except Exception as e:
        log_message(f"ERROR: {e}")
        raise

def extract_features_batched(packets, analyser, batch_size=5000):
    """Extract features in batches to manage memory"""
    print(f"\nExtracting features from {len(packets):,} packets...")
    
    flow_features = []
    total = len(packets)
    
    start_time = time.time()
    
    for i in range(0, total, batch_size):
        batch = packets[i:i+batch_size]
        batch_features = []
        
        for pkt in batch:
            features = analyser.analyze_packet(pkt)
            if features:
                batch_features.append(features)
        
        flow_features.extend(batch_features)
        
        processed = min(i + batch_size, total)
        percentage = (processed / total) * 100
        
        elapsed = time.time() - start_time
        rate = processed / elapsed if elapsed > 0 else 0
        remaining = (total - processed) / rate if rate > 0 else 0
        
        print(f"  {processed:,}/{total:,} ({percentage:.1f}%) | "
              f"Rate: {rate:.0f}/s | "
              f"ETA: {remaining//60:.0f}m {remaining%60:.0f}s | "
              f"Features: {len(flow_features):,}")
    
    return flow_features

def train_overnight_model(flow_features, contamination):
    """Train with overnight dataset"""
    import numpy as np
    
    print("\n" + "="*70)
    print("OVERNIGHT MODEL TRAINING")
    print("="*70)
    print(f"Training samples: {len(flow_features):,}")
    print(f"Contamination: {contamination*100}%")
    print()
    
    ml_model = FlowMLModel(contamination=contamination)
    
    print("Training model (this may take a few minutes for large datasets)...")
    train_start = time.time()
    ml_model.train(flow_features)
    train_time = time.time() - train_start
    
    print(f"Training complete in {train_time:.2f}s ({len(flow_features)/train_time:.0f} samples/s)\n")
    
    # Validation
    print("Running validation...")
    val_start = time.time()
    predictions = ml_model.predict(flow_features)
    scores = ml_model.anomaly_score(flow_features)
    val_time = time.time() - val_start
    
    anomaly_count = sum(1 for p in predictions if p == -1)
    normal_count = len(predictions) - anomaly_count
    anomaly_percentage = (anomaly_count / len(predictions)) * 100
    
    print(f"Validation complete in {val_time:.2f}s\n")
    
    print("="*70)
    print("VALIDATION RESULTS")
    print("="*70)
    print(f"Total samples: {len(flow_features):,}")
    print(f"Normal: {normal_count:,} ({100-anomaly_percentage:.2f}%)")
    print(f"Anomalies: {anomaly_count:,} ({anomaly_percentage:.2f}%)")
    print()
    print(f"Score Distribution:")
    print(f"  Min: {np.min(scores):.4f}")
    print(f"  25%: {np.percentile(scores, 25):.4f}")
    print(f"  50%: {np.median(scores):.4f}")
    print(f"  75%: {np.percentile(scores, 75):.4f}")
    print(f"  Max: {np.max(scores):.4f}")
    print("="*70)
    
    return ml_model

def cleanup_checkpoints(checkpoint_dir):
    """Clean up checkpoint files"""
    import shutil
    
    if os.path.exists(checkpoint_dir):
        response = input(f"\nDelete checkpoint files in {checkpoint_dir}? (y/n): ")
        if response.lower() == 'y':
            shutil.rmtree(checkpoint_dir)
            print("Checkpoints deleted")

def main():
    print("="*70)
    print("OVERNIGHT BASELINE TRAINING MODE")
    print("="*70)
    print(f"Target: {TARGET_PACKETS:,} packets")
    print(f"Duration: Up to {CAPTURE_DURATION//3600} hours")
    print(f"Contamination: {CONTAMINATION*100}%")
    print(f"Output: {MODEL_PATH}")
    print("="*70)
    
    # Estimates
    estimate_final_size()
    
    # Select interface
    interface = select_interface()
    if not interface:
        print("ERROR: No active network interface found")
        sys.exit(1)
    
    # Instructions
    print_overnight_instructions()
    
    # Confirm
    print("IMPORTANT: Disable sleep mode before starting!")
    response = input("Ready to begin overnight training? Press ENTER to start: ")
    print()
    
    # Initialize
    analyser = TrafficAnalysis()
    
    try:
        # Capture
        packets = capture_overnight_baseline(interface, TARGET_PACKETS, 
                                            CAPTURE_DURATION, CHECKPOINT_DIR)
        
        if len(packets) < 10000:
            print(f"\nWARNING: Only {len(packets):,} packets captured")
            print("Recommended minimum: 10,000 for overnight training")
            response = input("Continue anyway? (y/n): ")
            if response.lower() != 'y':
                sys.exit(1)
        
        # Extract features
        flow_features = extract_features_batched(packets, analyser)
        
        if not flow_features:
            print("\nERROR: No features extracted")
            sys.exit(1)
        
        extraction_rate = (len(flow_features) / len(packets)) * 100
        print(f"\nExtracted {len(flow_features):,} features ({extraction_rate:.1f}%)")
        
        # Train
        ml_model = train_overnight_model(flow_features, CONTAMINATION)
        
        # Save
        print(f"\nSaving model to {MODEL_PATH}...")
        ml_model.save(MODEL_PATH)
        
        model_size = os.path.getsize(MODEL_PATH) / (1024 * 1024)
        print(f"Model saved successfully ({model_size:.2f} MB)")
        
        print("\n" + "="*70)
        print("OVERNIGHT TRAINING COMPLETE!")
        print("="*70)
        print(f"Model: {MODEL_PATH} ({model_size:.2f} MB)")
        print(f"Training samples: {len(flow_features):,}")
        print(f"Contamination: {CONTAMINATION*100}%")
        print()
        print("This is your ultimate baseline model.")
        print("Use it with main.py for highly accurate anomaly detection.")
        print("="*70)
        
        # Cleanup
        cleanup_checkpoints(CHECKPOINT_DIR)
        
    except KeyboardInterrupt:
        print("\n\nTraining cancelled")
        sys.exit(1)
    except Exception as e:
        print(f"\nERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
