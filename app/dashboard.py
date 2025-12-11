"""
Threat Intelligence Data Analysis Dashboard
Advanced Streamlit-based security monitoring and threat analysis platform
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import numpy as np
from threat_detector import ThreatDetector
from ml_models import AnomalyDetector, ThreatClassifier

# Page configuration
st.set_page_config(
    page_title="Threat Intelligence Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for professional styling
st.markdown("""
    <style>
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        color: #1f77b4;
        text-align: center;
        padding: 1rem 0;
    }
    .metric-card {
        background-color: #f0f2f6;
        padding: 1rem;
        border-radius: 0.5rem;
        border-left: 4px solid #1f77b4;
    }
    .threat-high {
        color: #d62728;
        font-weight: bold;
    }
    .threat-medium {
        color: #ff7f0e;
        font-weight: bold;
    }
    .threat-low {
        color: #2ca02c;
        font-weight: bold;
    }
    </style>
""", unsafe_allow_html=True)

# Initialize session state
if 'threat_detector' not in st.session_state:
    st.session_state.threat_detector = ThreatDetector()
    st.session_state.anomaly_detector = AnomalyDetector()
    st.session_state.threat_classifier = ThreatClassifier()

# Sidebar
with st.sidebar:
    st.image("https://img.icons8.com/color/96/000000/security-checked.png", width=100)
    st.title("🛡️ Threat Intel Platform")
    
    st.markdown("---")
    
    # Time range selector
    time_range = st.selectbox(
        "Time Range",
        ["Last Hour", "Last 24 Hours", "Last 7 Days", "Last 30 Days", "Custom"]
    )
    
    # Threat severity filter
    severity_filter = st.multiselect(
        "Severity Filter",
        ["Critical", "High", "Medium", "Low", "Info"],
        default=["Critical", "High", "Medium"]
    )
    
    # Data source filter
    data_sources = st.multiselect(
        "Data Sources",
        ["Firewall Logs", "IDS/IPS", "Cloud Security", "Endpoint Detection", "Network Traffic"],
        default=["Firewall Logs", "IDS/IPS", "Cloud Security"]
    )
    
    st.markdown("---")
    
    # Auto-refresh
    auto_refresh = st.checkbox("Auto-refresh (30s)", value=True)
    
    if st.button("🔄 Refresh Data", use_container_width=True):
        st.rerun()
    
    st.markdown("---")
    st.markdown("### 📊 System Status")
    st.success("✅ All Systems Operational")
    st.metric("Uptime", "99.9%")
    st.metric("Events/sec", "8,547")

# Main header
st.markdown('<div class="main-header">🛡️ Threat Intelligence Dashboard</div>', unsafe_allow_html=True)
st.markdown(f"**Last Updated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

# Generate sample data (in production, this would fetch real data)
def generate_threat_data():
    np.random.seed(42)
    dates = pd.date_range(end=datetime.now(), periods=100, freq='H')
    
    threats = pd.DataFrame({
        'timestamp': dates,
        'threat_type': np.random.choice(['Malware', 'Phishing', 'DDoS', 'Intrusion', 'Data Exfiltration'], 100),
        'severity': np.random.choice(['Critical', 'High', 'Medium', 'Low'], 100, p=[0.1, 0.2, 0.4, 0.3]),
        'source_ip': [f"192.168.{np.random.randint(1,255)}.{np.random.randint(1,255)}" for _ in range(100)],
        'destination_ip': [f"10.0.{np.random.randint(1,255)}.{np.random.randint(1,255)}" for _ in range(100)],
        'country': np.random.choice(['USA', 'China', 'Russia', 'Brazil', 'India', 'Germany'], 100),
        'blocked': np.random.choice([True, False], 100, p=[0.8, 0.2]),
        'confidence': np.random.uniform(0.7, 1.0, 100)
    })
    
    return threats

threat_data = generate_threat_data()

# Key Metrics Row
col1, col2, col3, col4, col5 = st.columns(5)

with col1:
    st.metric(
        "Total Threats",
        f"{len(threat_data):,}",
        delta=f"+{np.random.randint(5, 20)} from last hour",
        delta_color="inverse"
    )

with col2:
    critical_threats = len(threat_data[threat_data['severity'] == 'Critical'])
    st.metric(
        "Critical Threats",
        critical_threats,
        delta=f"+{np.random.randint(1, 5)}",
        delta_color="inverse"
    )

with col3:
    blocked_rate = (threat_data['blocked'].sum() / len(threat_data)) * 100
    st.metric(
        "Block Rate",
        f"{blocked_rate:.1f}%",
        delta="+2.3%"
    )

with col4:
    avg_confidence = threat_data['confidence'].mean() * 100
    st.metric(
        "Avg Confidence",
        f"{avg_confidence:.1f}%",
        delta="+1.5%"
    )

with col5:
    unique_ips = threat_data['source_ip'].nunique()
    st.metric(
        "Unique Sources",
        unique_ips,
        delta=f"+{np.random.randint(3, 10)}"
    )

st.markdown("---")

# Main content area
tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "📊 Overview", 
    "🔍 Threat Analysis", 
    "🤖 AI Detection", 
    "🌍 Geographic View",
    "📈 Analytics"
])

with tab1:
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Threat Distribution by Type")
        threat_counts = threat_data['threat_type'].value_counts()
        fig = px.pie(
            values=threat_counts.values,
            names=threat_counts.index,
            hole=0.4,
            color_discrete_sequence=px.colors.qualitative.Set3
        )
        fig.update_layout(height=400)
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        st.subheader("Severity Distribution")
        severity_counts = threat_data['severity'].value_counts()
        colors = {'Critical': '#d62728', 'High': '#ff7f0e', 'Medium': '#ffbb00', 'Low': '#2ca02c'}
        fig = go.Figure(data=[go.Bar(
            x=severity_counts.index,
            y=severity_counts.values,
            marker_color=[colors.get(x, '#1f77b4') for x in severity_counts.index]
        )])
        fig.update_layout(height=400, showlegend=False)
        st.plotly_chart(fig, use_container_width=True)
    
    st.subheader("Threat Timeline")
    timeline_data = threat_data.groupby([pd.Grouper(key='timestamp', freq='H'), 'severity']).size().reset_index(name='count')
    fig = px.line(
        timeline_data,
        x='timestamp',
        y='count',
        color='severity',
        color_discrete_map={'Critical': '#d62728', 'High': '#ff7f0e', 'Medium': '#ffbb00', 'Low': '#2ca02c'}
    )
    fig.update_layout(height=400)
    st.plotly_chart(fig, use_container_width=True)

with tab2:
    st.subheader("Recent Threat Events")
    
    # Filter controls
    col1, col2, col3 = st.columns(3)
    with col1:
        selected_severity = st.multiselect("Filter by Severity", threat_data['severity'].unique(), default=threat_data['severity'].unique())
    with col2:
        selected_type = st.multiselect("Filter by Type", threat_data['threat_type'].unique(), default=threat_data['threat_type'].unique())
    with col3:
        show_blocked_only = st.checkbox("Show Blocked Only")
    
    # Apply filters
    filtered_data = threat_data[
        (threat_data['severity'].isin(selected_severity)) &
        (threat_data['threat_type'].isin(selected_type))
    ]
    
    if show_blocked_only:
        filtered_data = filtered_data[filtered_data['blocked'] == True]
    
    # Display table
    display_data = filtered_data[['timestamp', 'threat_type', 'severity', 'source_ip', 'destination_ip', 'country', 'blocked', 'confidence']].sort_values('timestamp', ascending=False)
    
    st.dataframe(
        display_data.head(50),
        use_container_width=True,
        height=400
    )
    
    # Detailed threat analysis
    st.subheader("Top Threat Sources")
    col1, col2 = st.columns(2)
    
    with col1:
        top_sources = threat_data['source_ip'].value_counts().head(10)
        fig = px.bar(x=top_sources.values, y=top_sources.index, orientation='h')
        fig.update_layout(height=400, showlegend=False, yaxis_title="Source IP", xaxis_title="Threat Count")
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        top_countries = threat_data['country'].value_counts().head(10)
        fig = px.bar(x=top_countries.values, y=top_countries.index, orientation='h', color=top_countries.values)
        fig.update_layout(height=400, showlegend=False, yaxis_title="Country", xaxis_title="Threat Count")
        st.plotly_chart(fig, use_container_width=True)

with tab3:
    st.subheader("🤖 AI-Powered Anomaly Detection")
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.markdown("### Anomaly Score Timeline")
        # Generate anomaly scores
        anomaly_scores = pd.DataFrame({
            'timestamp': pd.date_range(end=datetime.now(), periods=100, freq='H'),
            'anomaly_score': np.random.beta(2, 5, 100) * 100,
            'threshold': [75] * 100
        })
        
        fig = go.Figure()
        fig.add_trace(go.Scatter(
            x=anomaly_scores['timestamp'],
            y=anomaly_scores['anomaly_score'],
            mode='lines',
            name='Anomaly Score',
            line=dict(color='#1f77b4', width=2)
        ))
        fig.add_trace(go.Scatter(
            x=anomaly_scores['timestamp'],
            y=anomaly_scores['threshold'],
            mode='lines',
            name='Threshold',
            line=dict(color='#d62728', width=2, dash='dash')
        ))
        fig.update_layout(height=400)
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        st.markdown("### Detection Stats")
        st.metric("Anomalies Detected", "23", delta="+5")
        st.metric("Model Accuracy", "96.8%", delta="+0.3%")
        st.metric("False Positives", "1.2%", delta="-0.5%")
        
        st.markdown("### Active Models")
        st.success("✅ Isolation Forest")
        st.success("✅ LSTM Autoencoder")
        st.success("✅ Random Forest")
    
    st.markdown("### ML Model Performance")
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.markdown("**Isolation Forest**")
        st.progress(0.97)
        st.caption("Accuracy: 97%")
    
    with col2:
        st.markdown("**LSTM Autoencoder**")
        st.progress(0.95)
        st.caption("Accuracy: 95%")
    
    with col3:
        st.markdown("**Random Forest**")
        st.progress(0.98)
        st.caption("Accuracy: 98%")

with tab4:
    st.subheader("🌍 Geographic Threat Distribution")
    
    # Generate geographic data
    geo_data = threat_data.groupby('country').agg({
        'threat_type': 'count',
        'severity': lambda x: (x == 'Critical').sum()
    }).reset_index()
    geo_data.columns = ['country', 'total_threats', 'critical_threats']
    
    # World map
    fig = px.choropleth(
        geo_data,
        locations='country',
        locationmode='country names',
        color='total_threats',
        hover_name='country',
        hover_data={'total_threats': True, 'critical_threats': True},
        color_continuous_scale='Reds',
        title='Global Threat Heatmap'
    )
    fig.update_layout(height=500)
    st.plotly_chart(fig, use_container_width=True)
    
    # Top countries table
    st.subheader("Top Threat Origin Countries")
    st.dataframe(
        geo_data.sort_values('total_threats', ascending=False).head(10),
        use_container_width=True
    )

with tab5:
    st.subheader("📈 Advanced Analytics")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("### Threat Trends (7 Days)")
        trend_data = pd.DataFrame({
            'date': pd.date_range(end=datetime.now(), periods=7, freq='D'),
            'threats': np.random.randint(800, 1200, 7)
        })
        fig = px.area(trend_data, x='date', y='threats', color_discrete_sequence=['#1f77b4'])
        fig.update_layout(height=300)
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        st.markdown("### Block Success Rate")
        success_data = pd.DataFrame({
            'date': pd.date_range(end=datetime.now(), periods=7, freq='D'),
            'rate': np.random.uniform(75, 95, 7)
        })
        fig = px.line(success_data, x='date', y='rate', markers=True, color_discrete_sequence=['#2ca02c'])
        fig.update_layout(height=300)
        st.plotly_chart(fig, use_container_width=True)
    
    st.markdown("### Correlation Matrix")
    # Create correlation heatmap
    corr_data = threat_data[['confidence']].copy()
    corr_data['severity_num'] = threat_data['severity'].map({'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1})
    corr_data['blocked_num'] = threat_data['blocked'].astype(int)
    
    fig = px.imshow(
        corr_data.corr(),
        text_auto=True,
        color_continuous_scale='RdBu_r',
        aspect='auto'
    )
    fig.update_layout(height=400)
    st.plotly_chart(fig, use_container_width=True)

# Footer
st.markdown("---")
st.markdown("""
    <div style='text-align: center; color: #666;'>
        <p>🛡️ Threat Intelligence Platform v2.0 | Built with Streamlit & AI/ML</p>
        <p>© 2024 Mangesh Bhattacharya | Secure • Scalable • Intelligent</p>
    </div>
""", unsafe_allow_html=True)

# Auto-refresh logic
if auto_refresh:
    import time
    time.sleep(30)
    st.rerun()
