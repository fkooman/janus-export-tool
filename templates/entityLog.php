<html>
<head>
<title>Configuration Log</title>
<style>
    body {
        font-family: sans-serif;
    }
    table {
        border: 1px solid #000;
        border-collapse: collapse;
    }
    td, th {
        border: 1px dotted #000;
    padding: 5px;
    }
    span.prodaccepted {
        color: #080;
    }
    span.testaccepted {
        color: #888;
    }
    div.timestamp {
    float: right;
    }
</style>
</head>
<body>

<h1>Entity Log</h1>

<div class="timestamp">
    <small>Generated at <em><?php echo $dateTime; ?></em></small>
</div>

<ul>
<?php foreach (array_keys($data) as $set) { ?>
    <li><a href="#<?php echo $set; ?>"><?php echo $set; ?></a></li>
<?php } ?>
</ul>

<?php foreach ($data as $set => $entities) { ?>
    <h2 id="<?php echo $set; ?>"><?php echo $set; ?></h2>

    <table>
    <thead>
        <tr><th>Entity ID</th><th>State</th><th>Messages</th></tr>
    </thead>
    <tbody>
    <?php foreach ($entities as $k => $v) { ?>
        <tr>
            <td><a target="_blank" href="<?php echo $janusHost; ?>/simplesaml/module.php/janus/editentity.php?eid=<?php echo $v['eid']; ?>"><?php echo $k; ?></a></td>
            <td><span class="<?php echo $v['state']; ?>"><?php echo $v['state']; ?></span></td>
            <td><ul>
            <?php foreach ($v['messages'] as $m) { ?>
                <li><?php echo $m['message']; ?></li>
            <?php } ?>
            </ul></td></tr>
    <?php } ?>
    </tbody>
    </table>
<?php } ?>
</body>
</html>
