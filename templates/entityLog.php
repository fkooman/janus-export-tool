<html>
<head>
<title>Janus Entity Log</title>
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
    span.WARNING {
        color: black;
    }
    span.ERROR {
        color: red;
    }
</style>
</head>
<body>

<h1>Janus Entity Log</h1>

<div class="timestamp">
    <small>Generated at <em><?php echo $dateTime; ?></em></small>
</div>

<ul>
<li>Production
<ul>
<?php foreach (array_keys($prodAcceptedData) as $set) { ?>
    <li><a href="#prod-<?php echo $set; ?>"><?php echo $set; ?></a></li>
<?php } ?>
</ul>
</li>
</ul>

<ul>
<li>Test (DIY)
<ul>
<?php foreach (array_keys($testAcceptedData) as $set) { ?>
    <li><a href="#test-<?php echo $set; ?>"><?php echo $set; ?></a></li>
<?php } ?>
</ul>
</li>
</ul>

<h1 id="prod">Production</h1>
<?php foreach ($prodAcceptedData as $set => $entities) { ?>
    <h2 id="prod-<?php echo $set; ?>"><?php echo $set; ?></h2>

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
                <li><span class="<?php echo $m['level']; ?>"><?php echo $m['message']; ?></span></li>
            <?php } ?>
            </ul></td></tr>
    <?php } ?>
    </tbody>
    </table>
<?php } ?>

<h1 id="test">Test (DIY)</h1>
<?php foreach ($testAcceptedData as $set => $entities) { ?>
    <h2 id="test-<?php echo $set; ?>"><?php echo $set; ?></h2>

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
