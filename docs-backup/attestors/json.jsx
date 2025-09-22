import React, { useState, useEffect } from 'react';

const JSONRenderer = ({ url }) => {
    const [jsonData, setJsonData] = useState(null);

    useEffect(() => {
        fetch(url)
            .then(response => response.json())
            .then(data => setJsonData(data))
            .catch(error => console.error('Error fetching JSON:', error));
    }, [url]);

    if (!jsonData) {
        return <div>Loading JSON data...</div>;
    }

    return (
        <pre>
            {JSON.stringify(jsonData, null, 2)}
        </pre>
    );
};

export default JSONRenderer;
