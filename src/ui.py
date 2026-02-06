import gradio as gr
import json
import os
from .models import RunConfig, TargetType
from .engine import ReconEngine
from .config import PROFILES, DEFAULT_CONCURRENCY, DEFAULT_CONNECT_TIMEOUT, TOP_100_PORTS
from .storage.writer import ResultWriter

def get_profile_defaults(profile_name):
    p = PROFILES.get(profile_name, PROFILES["Custom"])
    return (
        p["modules"], 
        p["concurrency"], 
        p["timeout"]
    )

def execute_scan(target, auth_checked, profile, modules, concurrency, timeout):
    if not auth_checked:
        return "⚠️ ERROR: You must acknowledge authorization to scan this target.", None, None

    if not target:
        return "⚠️ ERROR: Please enter a valid target.", None, None

    # Construct Config
    # Auto-detect type is handled by engine/utils validation, 
    # but RunConfig needs a type enum. We'll set a temporary one and let engine validate.
    # Actually validation splits it. 
    # For RunConfig, let's look at what we need.
    
    # We'll default to DOMAIN, let engine fix it? 
    # Or just passing string is enough if we loosen RunConfig or Helper?
    # Let's map it roughly.
    t_type = TargetType.DOMAIN 
    if "/" in target: t_type = TargetType.CIDR
    elif target.replace(".","").isdigit(): t_type = TargetType.IP
    elif target.startswith("http"): t_type = TargetType.URL
    
    # If "Custom" is not selected, user overrides are ignored? 
    # Or we just take the current UI values (which might have been updated by profile change)
    # The UI flow: Profile Select -> Updates Chkboxes/Sliders -> User clicks Run.
    # So we trust the `modules`, `concurrency`, `timeout` inputs passed to this function.
    
    cfg = RunConfig(
        target_input=target,
        target_type=t_type,
        profile_name=profile,
        enabled_modules=modules,
        concurrency=int(concurrency),
        connect_timeout=float(timeout)
    )
    
    engine = ReconEngine()
    
    # Run
    status_msg = f"🚀 Starting scan on {target} ({profile})...\n"
    yield status_msg, None, None
    
    try:
        result = engine.run(cfg)
        
        # Save
        writer = ResultWriter()
        saved_path = writer.save(result)
        
        # Format Summary
        sum_text = f"## ✅ Scan Complete\n"
        sum_text += f"- **Target**: `{result.summary.target}`\n"
        sum_text += f"- **IP Class**: `{result.summary.ip_class.upper()}`\n"
        sum_text += f"- **Duration**: {result.summary.duration_total:.2f}s\n"
        sum_text += f"- **Open Ports**: {result.summary.open_ports_total} {result.summary.open_ports_list}\n"
        sum_text += f"- **Subdomains**: {result.summary.subdomains_found}\n"
        if result.summary.cidr_notes:
            sum_text += f"- **CIDR Info**: {result.summary.cidr_notes}\n"
        
        # Risk Tags
        if result.summary.risk_tags:
            sum_text += f"\n### ⚠️ Risk Findings\n"
            for tag in result.summary.risk_tags:
                desc = result.summary.risk_details.get(tag, "")
                sum_text += f"- 🔴 **{tag}**: {desc}\n"
        
        # Module Timings
        if result.summary.module_timings:
            sum_text += f"\n### ⏱️ Module Timings\n"
            for m, t in result.summary.module_timings.items():
                sum_text += f"- **{m.upper()}**: {t:.2f}s\n"
        
        yield sum_text, result.dict(), saved_path
        
    except Exception as e:
        yield f"❌ Error during scan: {str(e)}", None, None

def build_ui():
    with gr.Blocks(title="ReconForge") as demo:
        gr.Markdown("# 🦅 ReconForge\n**Authorized Security Reconnaissance Tool**")
        
        with gr.Row():
            with gr.Column(scale=2):
                target_input = gr.Textbox(label="Target (Domain, IP, URL, CIDR)", placeholder="example.com")
                auth_checkbox = gr.Checkbox(label="✅ I have explicit written authorization to scan this target.", value=False)
                
                with gr.Row():
                    profile_radio = gr.Radio(
                        choices=list(PROFILES.keys()), 
                        value="Fast", 
                        label="Scan Profile"
                    )
                    gr.Markdown("""
                    - **Fast**: Passive Recon + Top 100 Ports
                    - **Full**: Passive + Web Probe + Top 1000 Ports
                    - **Custom**: User defined
                    """)
                    run_btn = gr.Button("🔥 Run Scan", variant="primary")
            
            with gr.Column(scale=1):
                gr.Markdown("### Advanced Settings")
                with gr.Accordion("Configuration", open=True):
                    module_options = ["dns", "whois", "subdomains", "ports", "web"]
                    modules_chk = gr.CheckboxGroup(
                        choices=module_options,
                        value=PROFILES["Fast"]["modules"],
                        label="Enabled Modules"
                    )
                    concurrency_slider = gr.Slider(1, 50, value=25, step=1, label="Concurrency")
                    timeout_slider = gr.Slider(0.1, 5.0, value=0.5, step=0.1, label="Timeout (s)")

        # Output Area
        with gr.Tabs():
            with gr.Tab("Summary"):
                status_output = gr.Markdown("Ready to scan.")
                download_file = gr.File(label="Download JSON Results")
            with gr.Tab("Raw JSON"):
                json_output = gr.JSON(label="Full Results")
                
        # Interactivity
        def update_settings(profile):
            defaults = get_profile_defaults(profile)
            return defaults[0], defaults[1], defaults[2]
            
        profile_radio.change(
            fn=update_settings,
            inputs=profile_radio,
            outputs=[modules_chk, concurrency_slider, timeout_slider]
        )
        
        run_btn.click(
            fn=execute_scan,
            inputs=[target_input, auth_checkbox, profile_radio, modules_chk, concurrency_slider, timeout_slider],
            outputs=[status_output, json_output, download_file]
        )
        
    return demo
